// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package shellintent

import "strings"

type tokKind int

const (
	tWord  tokKind = iota // an argument or command word, quotes already removed
	tSep                  // &&, ||, ;, |, &, newline, ( or )
	tRedir                // a redirection operator; the next word is its target
	tSub                  // the text of a $(...) or backtick substitution
)

type token struct {
	kind tokKind
	text string
	// quoted is true when any part of the word was quoted or escaped. A quoted
	// "{" or ">" is data, never a grouping brace or an operator.
	quoted bool
	// fd is the file descriptor digits written before a redirection ("2" in 2>).
	fd string
}

// lexer is a POSIX-ish word splitter. It exists so the hook can see the simple
// commands a line would run; it never expands anything. $VAR stays literal,
// and the only things it follows into are command substitutions, because those
// execute code the surrounding line does not show.
type lexer struct {
	s      string
	toks   []token
	cur    strings.Builder
	inWord bool
	quoted bool
	fail   string
	// pending are heredocs opened on the current line; their bodies start on
	// the next line and are skipped there.
	pending []heredoc
}

func tokenize(s string) ([]token, string) {
	lx := &lexer{s: s}
	lx.run()
	return lx.toks, lx.fail
}

func (lx *lexer) flush() {
	if lx.inWord {
		lx.toks = append(lx.toks, token{kind: tWord, text: lx.cur.String(), quoted: lx.quoted})
		lx.cur.Reset()
		lx.inWord, lx.quoted = false, false
	}
}

func (lx *lexer) sep(text string) {
	lx.flush()
	lx.toks = append(lx.toks, token{kind: tSep, text: text})
}

func (lx *lexer) run() {
	s := lx.s
	for i := 0; i < len(s) && lx.fail == ""; {
		c := s[i]
		switch c {
		case ' ', '\t', '\r':
			lx.flush()
			i++
		case '\n':
			lx.flush()
			i = lx.heredocBodies(i + 1)
			lx.sep("\n")
		case '#':
			if lx.inWord {
				lx.cur.WriteByte(c)
				i++
				continue
			}
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case '\\':
			i = lx.backslash(i)
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				lx.fail = "unbalanced single quote"
				return
			}
			lx.cur.WriteString(s[i+1 : i+1+end])
			lx.inWord, lx.quoted = true, true
			i += end + 2
		case '"':
			i = lx.doubleQuoted(i)
		case '`':
			i = lx.backtick(i)
		case '$':
			i = lx.dollar(i)
		case '<', '>':
			i = lx.redirect(i)
		case '&':
			switch {
			case strings.HasPrefix(s[i:], "&&"):
				lx.sep("&&")
				i += 2
			case strings.HasPrefix(s[i:], "&>>"):
				lx.flush()
				lx.toks = append(lx.toks, token{kind: tRedir, text: "&>>"})
				i += 3
			case strings.HasPrefix(s[i:], "&>"):
				lx.flush()
				lx.toks = append(lx.toks, token{kind: tRedir, text: "&>"})
				i += 2
			default:
				lx.sep("&")
				i++
			}
		case '|':
			switch {
			case strings.HasPrefix(s[i:], "||"):
				lx.sep("||")
				i += 2
			case strings.HasPrefix(s[i:], "|&"):
				lx.sep("|")
				i += 2
			default:
				lx.sep("|")
				i++
			}
		case ';', '(', ')':
			lx.sep(string(c))
			i++
		default:
			lx.cur.WriteByte(c)
			lx.inWord = true
			i++
		}
	}
	lx.flush()
	if lx.fail == "" && len(lx.pending) > 0 {
		lx.fail = "unterminated heredoc"
	}
}

// heredoc is a <<WORD or <<-WORD here-document.
type heredoc struct {
	delim string
	// strip is true for <<-, which ignores leading tabs on the closing line.
	strip bool
	// quoted is true when the delimiter was quoted, which stops the body from
	// undergoing command substitution.
	quoted bool
}

// heredocDelim reads the delimiter after "<<" (s[i] is the next byte).
func heredocDelim(s string, i int) (h heredoc, next int, ok bool) {
	if i < len(s) && s[i] == '-' {
		h.strip = true
		i++
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	var b strings.Builder
	start := i
loop:
	for i < len(s) {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\r', ';', '&', '|', '(', ')', '<', '>':
			break loop
		case '\'', '"':
			end := strings.IndexByte(s[i+1:], c)
			if end < 0 {
				return h, 0, false
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 2
			h.quoted = true
		case '\\':
			if i+1 >= len(s) {
				return h, 0, false
			}
			b.WriteByte(s[i+1])
			i += 2
			h.quoted = true
		default:
			b.WriteByte(c)
			i++
		}
	}
	if i == start || b.Len() == 0 {
		return h, 0, false
	}
	h.delim = b.String()
	return h, i, true
}

// heredocBody finds the end of a here-document whose body starts at s[i]. It
// returns the index just past the closing line and the body text.
func heredocBody(s string, i int, h heredoc) (end int, body string, ok bool) {
	for pos := i; pos <= len(s); {
		nl := strings.IndexByte(s[pos:], '\n')
		line, next := s[pos:], len(s)
		if nl >= 0 {
			line, next = s[pos:pos+nl], pos+nl+1
		}
		cmp := line
		if h.strip {
			cmp = strings.TrimLeft(line, "\t")
		}
		if cmp == h.delim {
			return next, s[i:pos], true
		}
		if nl < 0 {
			break
		}
		pos = next
	}
	return 0, "", false
}

// bodySubstitutions returns the command substitutions in an unquoted heredoc
// body: those run even though the rest of the body is only data.
func bodySubstitutions(body string) []string {
	var subs []string
	for j := 0; j < len(body); j++ {
		switch body[j] {
		case '\\':
			j++
		case '$':
			if j+1 < len(body) && body[j+1] == '(' {
				end, ok := matchParen(body, j+2)
				if !ok {
					return subs
				}
				if !strings.HasPrefix(body[j:], "$((") {
					subs = append(subs, body[j+2:end])
				}
				j = end
			}
		case '`':
			end, ok := matchBacktick(body, j+1)
			if !ok {
				return subs
			}
			subs = append(subs, strings.NewReplacer("\\`", "`", "\\\\", "\\", "\\$", "$").Replace(body[j+1:end]))
			j = end
		}
	}
	return subs
}

// heredocBodies skips the bodies of heredocs opened on the line that just
// ended. i is the index of the first byte after that line's newline; the
// result is the index where lexing resumes. An unquoted body's command
// substitutions are kept as tokens, because they still execute.
func (lx *lexer) heredocBodies(i int) int {
	for _, h := range lx.pending {
		end, body, ok := heredocBody(lx.s, i, h)
		if !ok {
			lx.fail = "unterminated heredoc"
			return len(lx.s)
		}
		if !h.quoted {
			for _, sub := range bodySubstitutions(body) {
				lx.toks = append(lx.toks, token{kind: tSub, text: sub})
			}
		}
		i = end
	}
	lx.pending = nil
	return i
}

// backslash handles an escape outside quotes. A trailing backslash-newline is
// a line continuation and vanishes.
func (lx *lexer) backslash(i int) int {
	s := lx.s
	if i+1 >= len(s) {
		lx.cur.WriteByte('\\')
		lx.inWord = true
		return i + 1
	}
	if s[i+1] == '\n' {
		return i + 2
	}
	lx.cur.WriteByte(s[i+1])
	lx.inWord, lx.quoted = true, true
	return i + 2
}

// doubleQuoted consumes a double-quoted run starting at s[i] == '"'. Command
// substitutions inside double quotes still execute, so they are recorded.
func (lx *lexer) doubleQuoted(i int) int {
	s := lx.s
	lx.inWord, lx.quoted = true, true
	for k := i + 1; k < len(s); {
		switch s[k] {
		case '"':
			return k + 1
		case '\\':
			if k+1 >= len(s) {
				lx.cur.WriteByte('\\')
				k++
				continue
			}
			switch s[k+1] {
			case '$', '`', '"', '\\':
				lx.cur.WriteByte(s[k+1])
			case '\n':
			default:
				lx.cur.WriteByte('\\')
				lx.cur.WriteByte(s[k+1])
			}
			k += 2
		case '$':
			k = lx.dollar(k)
			if lx.fail != "" {
				return len(s)
			}
		case '`':
			k = lx.backtick(k)
			if lx.fail != "" {
				return len(s)
			}
		default:
			lx.cur.WriteByte(s[k])
			k++
		}
	}
	lx.fail = "unbalanced double quote"
	return len(s)
}

// dollar handles s[i] == '$'. $(( )) arithmetic is kept literal; $( ) is
// recorded for recursive parsing; everything else, including ${VAR}, stays as
// typed.
func (lx *lexer) dollar(i int) int {
	s := lx.s
	lx.inWord = true
	if i+1 < len(s) && s[i+1] == '(' {
		end, ok := matchParen(s, i+2)
		if !ok {
			lx.fail = "unbalanced $( substitution"
			return len(s)
		}
		if !strings.HasPrefix(s[i:], "$((") {
			lx.toks = append(lx.toks, token{kind: tSub, text: s[i+2 : end]})
		}
		lx.cur.WriteString(s[i : end+1])
		return end + 1
	}
	lx.cur.WriteByte('$')
	return i + 1
}

func (lx *lexer) backtick(i int) int {
	s := lx.s
	lx.inWord = true
	end, ok := matchBacktick(s, i+1)
	if !ok {
		lx.fail = "unbalanced backtick"
		return len(s)
	}
	inner := strings.NewReplacer("\\`", "`", "\\\\", "\\", "\\$", "$").Replace(s[i+1 : end])
	lx.toks = append(lx.toks, token{kind: tSub, text: inner})
	lx.cur.WriteString(s[i : end+1])
	return end + 1
}

// redirect lexes < and > forms. A heredoc is stdin text, skipped at the end of
// its line. Process substitution runs a command the lexer does not follow, so it
// fails the parse.
func (lx *lexer) redirect(i int) int {
	s := lx.s
	fd := ""
	if lx.inWord && !lx.quoted && isDigits(lx.cur.String()) {
		fd = lx.cur.String()
		lx.cur.Reset()
		lx.inWord = false
	} else {
		lx.flush()
	}
	var op string
	switch {
	case strings.HasPrefix(s[i:], "<<<"):
		op = "<<<"
	case strings.HasPrefix(s[i:], "<<"):
		h, next, ok := heredocDelim(s, i+2)
		if !ok {
			lx.fail = "heredoc without a delimiter"
			return len(s)
		}
		lx.pending = append(lx.pending, h)
		lx.toks = append(lx.toks, token{kind: tRedir, text: "<<", fd: fd}, token{kind: tWord, text: h.delim, quoted: true})
		return next
	case strings.HasPrefix(s[i:], "<("), strings.HasPrefix(s[i:], ">("):
		lx.fail = "process substitution"
		return len(s)
	case strings.HasPrefix(s[i:], "<&"), strings.HasPrefix(s[i:], "<>"):
		op = s[i : i+2]
	case strings.HasPrefix(s[i:], ">>"), strings.HasPrefix(s[i:], ">&"), strings.HasPrefix(s[i:], ">|"):
		op = s[i : i+2]
	default:
		op = s[i : i+1]
	}
	lx.toks = append(lx.toks, token{kind: tRedir, text: op, fd: fd})
	return i + len(op)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// matchParen returns the index of the ")" closing a "(" whose body starts at
// s[i], honoring quotes and nested substitutions.
func matchParen(s string, i int) (int, bool) {
	depth := 1
	var pending []heredoc
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '<':
			// A heredoc body may hold quotes and parentheses that are only text.
			if strings.HasPrefix(s[j:], "<<<") {
				j += 2
			} else if strings.HasPrefix(s[j:], "<<") {
				if h, next, ok := heredocDelim(s, j+2); ok {
					pending = append(pending, h)
					j = next - 1
				}
			}
		case '\n':
			start := j + 1
			for _, h := range pending {
				end, _, ok := heredocBody(s, start, h)
				if !ok {
					return 0, false
				}
				start = end
			}
			if len(pending) > 0 {
				pending = nil
				j = start - 1
			}
		case '\\':
			j++
		case '\'':
			k := strings.IndexByte(s[j+1:], '\'')
			if k < 0 {
				return 0, false
			}
			j += k + 1
		case '"':
			k, ok := skipDouble(s, j+1)
			if !ok {
				return 0, false
			}
			j = k
		case '`':
			k, ok := matchBacktick(s, j+1)
			if !ok {
				return 0, false
			}
			j = k
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j, true
			}
		}
	}
	return 0, false
}

// skipDouble returns the index of the quote closing a double-quoted run whose
// body starts at s[i].
func skipDouble(s string, i int) (int, bool) {
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j, true
		case '$':
			if j+1 < len(s) && s[j+1] == '(' {
				end, ok := matchParen(s, j+2)
				if !ok {
					return 0, false
				}
				j = end
			}
		case '`':
			end, ok := matchBacktick(s, j+1)
			if !ok {
				return 0, false
			}
			j = end
		}
	}
	return 0, false
}

func matchBacktick(s string, i int) (int, bool) {
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '`':
			return j, true
		}
	}
	return 0, false
}
