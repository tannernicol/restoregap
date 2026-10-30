// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

/*
 * Restore Gap - interactive recovery-graph renderer (self-contained, no deps).
 *
 * The core idea: recoverability is a CLOSED LOOP. A healthy recovery graph has a
 * directed cycle through the good-state node - the agent goes forward, and there
 * is a directed path BACK. That cycle is "the way back". A recovery-stranding
 * action severs the return arc: the loop snaps open, you can still go forward,
 * but nothing can reach the good state again. No path back = block. Proving the
 * way back closes the loop through a second arc.
 *
 * Public API: RestoreGapGraph.mount(rootEl, spec)
 *
 * Spec (see report/recovery_graph.py for the canonical builder):
 *   { surfaces: [ {
 *       id, label, tagline,
 *       nodes: [ { id, label, kind, sub?, root?, ghost? } ],  // root = good state
 *       edges: [ { from, to, type? } ],                        // directed: from -> to
 *       scenario: {
 *         actionNode, actionLabel, actionCmd,
 *         linter: { name, verdict, note },
 *         gate:   { verdict, missingProof, note },
 *         heal:   { label, revealNodes?, addEdges?, dropEdges? }
 *       } } ] }
 */
(function () {
  "use strict";

  // Brand palette (matches the site): violet primary for the way back; red for gaps.
  var PALETTE = {
    key: "#ffc24b", store: "#8b7cff", secret: "#b794ff", access: "#8b7cff",
    role: "#8b7cff", workflow: "#8b7cff", repo: "#8b7cff", org: "#b794ff",
    branch: "#9aa7ff", action: "#ffc24b", terraform: "#58d5c9", cloud: "#6ad7ff",
    vendor: "#6ad7ff", artifact: "#ffc24b", proof: "#46e0a0", goal: "#eef1f7",
    generic: "#8b7cff"
  };
  var RED = "#ff6076", AMBER = "#ffc24b", BRAND = "#8b7cff", BRAND2 = "#b794ff", CYAN = "#6ad7ff", GREEN = "#46e0a0";
  var WAYBACK = BRAND;
  var GROUPS = {
    github:    { x: -420, y: -148, z: 0, w: 430, h: 300, label: "GitHub control plane", color: BRAND },
    device:    { x: -300, y: -164, z: 0, w: 480, h: 270, label: "Device / system", color: "#ff8a5b" },
    terraform: { x: 40,   y: -176, z: 0, w: 300, h: 236, label: "Terraform declarations", color: "#58d5c9" },
    cloud:     { x: 420,  y: -142, z: 0, w: 330, h: 260, label: "Cloud resources", color: CYAN },
    vendor:    { x: 386,  y: 196,  z: 0, w: 330, h: 248, label: "Vendor coverage", color: "#ffc24b" },
    offline:   { x: -230, y: 214,  z: 0, w: 470, h: 278, label: "Offline mitigation", color: BRAND2 }
  };

  function hash(str) {
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return (h >>> 0) / 4294967295;
  }

  // ---- directed reachability ---------------------------------------------
  function adjacency(nodes, edges, dead) {
    var fwd = {}, rev = {}, i;
    for (i = 0; i < edges.length; i++) {
      var e = edges[i];
      if (!e._a || !e._b || e._a._hidden || e._b._hidden) continue;
      if (dead[e.from] || dead[e.to]) continue;
      (fwd[e.from] || (fwd[e.from] = [])).push(e.to);
      (rev[e.to] || (rev[e.to] = [])).push(e.from);
    }
    return { fwd: fwd, rev: rev };
  }
  function bfs(start, adj) {
    var seen = {}; seen[start] = true; var q = [start];
    while (q.length) {
      var u = q.pop(), nb = adj[u] || [];
      for (var i = 0; i < nb.length; i++) if (!seen[nb[i]]) { seen[nb[i]] = true; q.push(nb[i]); }
    }
    return seen;
  }

  // ---- 3D force layout ----------------------------------------------------
  function groupKey(nd) { return nd.group || "github"; }
  function groupFor(nd) { return GROUPS[groupKey(nd)] || GROUPS.github; }
  function clampToGroup(nd) {
    var g = groupFor(nd), pad = nd.root ? 42 : 30;
    nd._p.x = Math.max(g.x - g.w / 2 + pad, Math.min(g.x + g.w / 2 - pad, nd._p.x));
    nd._p.y = Math.max(g.y - g.h / 2 + pad, Math.min(g.y + g.h / 2 - pad, nd._p.y));
  }

  function anchor(nd, gi, total) {
    var g = GROUPS[nd.group || "github"] || GROUPS.github;
    if (nd.root) return { x: g.x, y: g.y + g.h * 0.28, z: 0 };
    var aspect = g.w / Math.max(1, g.h);
    var cols = Math.max(2, Math.ceil(Math.sqrt(Math.max(1, total) * aspect)));
    var rows = Math.max(1, Math.ceil(Math.max(1, total) / cols));
    var col = gi % cols, row = Math.floor(gi / cols);
    var px = 44, py = 46;
    var sx = cols === 1 ? 0.5 : col / (cols - 1);
    var sy = rows === 1 ? 0.5 : row / (rows - 1);
    return {
      x: g.x - g.w / 2 + px + sx * (g.w - px * 2) + (hash(nd.id + "jx") - 0.5) * 12,
      y: g.y - g.h / 2 + py + sy * (g.h - py * 2) + (hash(nd.id + "jy") - 0.5) * 12,
      z: (hash(nd.id + "z") - 0.5) * 28
    };
  }

  function layout(nodes, edges) {
    var i, j, n = nodes.length;
    var totals = {}, seen = {};
    for (i = 0; i < n; i++) if (!nodes[i]._hidden) totals[groupKey(nodes[i])] = (totals[groupKey(nodes[i])] || 0) + 1;
    for (i = 0; i < n; i++) {
      var nd = nodes[i];
      var gk = groupKey(nd), gi = seen[gk] || 0; seen[gk] = gi + (nd._hidden ? 0 : 1);
      nd._anchor = anchor(nd, gi, totals[gk] || 1);
      if (nd._p && nd._layoutGroup === (nd.group || "")) continue;
      nd._layoutGroup = nd.group || "";
      nd._p = { x: nd._anchor.x + (hash(nd.id + "jx") - 0.5) * 18,
                y: nd._anchor.y + (hash(nd.id + "jy") - 0.5) * 18,
                z: nd._anchor.z + (hash(nd.id + "jz") - 0.5) * 18 };
      nd._v = { x: 0, y: 0, z: 0 };
    }
    var REST = 48, SPRING = 0.012, REP = 5400, CENTER = 0.085, DAMP = 0.72;
    var live = nodes.filter(function (x) { return !x._hidden; });
    var ledges = edges.filter(function (e) { return e._a && e._b && !e._a._hidden && !e._b._hidden; });
    for (var it = 0; it < 620; it++) {
      for (i = 0; i < live.length; i++) live[i]._f = { x: 0, y: 0, z: 0 };
      for (i = 0; i < live.length; i++) {
        for (j = i + 1; j < live.length; j++) {
          var dx = live[i]._p.x - live[j]._p.x, dy = live[i]._p.y - live[j]._p.y, dz = live[i]._p.z - live[j]._p.z;
          var d2 = dx * dx + dy * dy + dz * dz + 0.01, d = Math.sqrt(d2), f = REP / d2;
          var ux = dx / d, uy = dy / d, uz = dz / d;
          live[i]._f.x += ux * f; live[i]._f.y += uy * f; live[i]._f.z += uz * f;
          live[j]._f.x -= ux * f; live[j]._f.y -= uy * f; live[j]._f.z -= uz * f;
        }
      }
      for (i = 0; i < ledges.length; i++) {
        var A = ledges[i]._a, B = ledges[i]._b;
        var ex = B._p.x - A._p.x, ey = B._p.y - A._p.y, ez = B._p.z - A._p.z;
        var ed = Math.sqrt(ex * ex + ey * ey + ez * ez) + 0.01, diff = (ed - REST) * SPRING;
        A._f.x += ex / ed * diff; A._f.y += ey / ed * diff; A._f.z += ez / ed * diff;
        B._f.x -= ex / ed * diff; B._f.y -= ey / ed * diff; B._f.z -= ez / ed * diff;
      }
      for (i = 0; i < live.length; i++) {
        var p = live[i]._p, v = live[i]._v, f = live[i]._f;
        var a0 = live[i]._anchor || { x: 0, y: 0, z: 0 };
        f.x += (a0.x - p.x) * CENTER; f.y += (a0.y - p.y) * CENTER;
        f.z += (a0.z - p.z) * CENTER;
        f.z -= p.z * 0.08; // flatten toward the viewing plane so labels stay readable
        if (live[i].root) f.y -= 0.6;
        v.x = (v.x + f.x) * DAMP; v.y = (v.y + f.y) * DAMP; v.z = (v.z + f.z) * DAMP;
        p.x += v.x; p.y += v.y; p.z += v.z;
        clampToGroup(live[i]);
      }
    }
  }

  // ---- per-surface controller --------------------------------------------
  function Scene(host, surface, reduced) {
    this.host = host; this.reduced = reduced;
    this.canvas = host.querySelector(".rg-canvas");
    this.ctx = this.canvas.getContext("2d");
    // Calm, head-on view of the recovery loop. No auto-rotation: the only
    // motion is the way-back flowing along the loop, and the snap when it breaks.
    this.yaw = 0; this.pitch = 0; this.dragging = false; this.autorot = false;
    this.cam = null; this.camTo = null; this._focusReq = null; this._needFit = false;
    this.hover = null; this.spotlight = null; this.t0 = performance.now(); this.wave = null;
    this.setSurface(surface);
    this._bind();
  }

  function noHide(n) { return !n._hidden; }

  Scene.prototype.setSurface = function (surface) {
    this.surface = surface;
    var byId = {}, i;
    this.nodes = surface.nodes.map(function (n) { return Object.assign({}, n); });
    for (i = 0; i < this.nodes.length; i++) {
      byId[this.nodes[i].id] = this.nodes[i];
      this.nodes[i]._hidden = !!this.nodes[i].ghost;
      if (this.nodes[i].root) this.rootId = this.nodes[i].id;
    }
    this.byId = byId;
    this.edges = surface.edges.map(function (e) {
      var c = Object.assign({}, e); c._a = byId[e.from]; c._b = byId[e.to]; return c;
    });
    this.healed = false; this.action = null; this.spotlight = null; this.hover = null; this._needFit = true;
    layout(this.nodes, this.edges);
    this.recompute();
  };

  Scene.prototype._reach = function (dead) {
    var adj = adjacency(this.nodes, this.edges, dead);
    return { from: bfs(this.rootId, adj.fwd), to: bfs(this.rootId, adj.rev) };
  };

  Scene.prototype.recompute = function () {
    var before = this._reach({});
    var dead = {}; if (this.action) dead[this.action] = true;
    var after = this._reach(dead);
    this.cur = this.action ? after : before;
    var live = this.nodes.filter(noHide), states = {}, stranded = 0, gaps = 0, noBack = 0, i;
    for (i = 0; i < live.length; i++) {
      var id = live[i].id, st;
      if (id === this.rootId) { st = "root"; }
      else if (this.action === id) { st = "dead"; noBack++; }
      else {
        var onBefore = before.from[id] && before.to[id];
        var onAfter = after.from[id] && after.to[id];
        if (!onBefore) { st = "gap"; gaps++; if (!onAfter) noBack++; }
        else if (!onAfter) { st = "stranded"; stranded++; noBack++; }
        else st = "ok";
      }
      states[id] = st;
    }
    this.states = states; this.stranded = stranded; this.gaps = gaps;
    // a recovery loop exists when some live successor of root can reach root
    this.cycleAfter = this._cycleExists(after);
    this.cycleBefore = this._cycleExists(before);
    // acting on a node that was never on a loop (e.g. a secret no vendor backs up)
    var actionGap = !!this.action && !!before.from[this.action] && !before.to[this.action];
    this.blocked = !!this.action && (stranded > 0 || !this.cycleAfter || actionGap);
    this.blast = noBack; // resources with no directed path back to the good state
  };

  Scene.prototype._cycleExists = function (reach) {
    for (var id in reach.from) {
      if (id === this.rootId) continue;
      if (reach.from[id] && reach.to[id]) return true; // root -> id -> ... -> root
    }
    return false;
  };

  Scene.prototype.simulate = function (id) {
    this.healed = false; this.setSurface(this.surface); this.action = id;
    this.recompute(); if (!this.reduced) this._startWave(id, RED);
    this.onChange && this.onChange();
  };

  Scene.prototype.heal = function () {
    var h = this.surface.scenario.heal, i;
    if (h) {
      if (h.revealNodes) for (i = 0; i < h.revealNodes.length; i++) {
        var nd = this.byId[h.revealNodes[i]]; if (nd) nd._hidden = false;
      }
      if (h.dropEdges) for (i = 0; i < h.dropEdges.length; i++) {
        var de = h.dropEdges[i];
        this.edges = this.edges.filter(function (e) { return !(e.from === de.from && e.to === de.to); });
      }
      if (h.addEdges) for (i = 0; i < h.addEdges.length; i++) {
        var ae = h.addEdges[i], c = Object.assign({}, ae);
        c._a = this.byId[ae.from]; c._b = this.byId[ae.to]; this.edges.push(c);
      }
    }
    this.healed = true; layout(this.nodes, this.edges); this.recompute();
    if (!this.reduced && h && h.revealNodes && h.revealNodes.length) this._startWave(h.revealNodes[0], GREEN);
    this.onChange && this.onChange();
  };

  Scene.prototype.reset = function () { this.setSurface(this.surface); this.wave = null; this.onChange && this.onChange(); };

  Scene.prototype.focusNode = function (id) {
    this.spotlight = id || null;
    this._focusReq = id || null;
  };

  Scene.prototype.refit = function () {
    this.spotlight = null; this.hover = null; this._needFit = true;
  };

  Scene.prototype.setFilter = function (group) {
    this.filter = group || null;
    this._needFit = true;
  };

  Scene.prototype.groupsPresent = function () {
    var present = {}, i, node;
    for (i = 0; i < this.nodes.length; i++) {
      node = this.nodes[i];
      if (!node._hidden) { present[node.group || "github"] = true; }
    }
    return present;
  };

  Scene.prototype._startWave = function (fromId, color) {
    var adj = {}, i;
    for (i = 0; i < this.edges.length; i++) {
      var e = this.edges[i];
      (adj[e.from] || (adj[e.from] = [])).push(e.to);
      (adj[e.to] || (adj[e.to] = [])).push(e.from);
    }
    var order = {}, q = [fromId], d = 0; order[fromId] = 0;
    while (q.length) {
      var nq = [];
      for (i = 0; i < q.length; i++) {
        var nb = adj[q[i]] || [];
        for (var j = 0; j < nb.length; j++) if (order[nb[j]] === undefined) { order[nb[j]] = d + 1; nq.push(nb[j]); }
      }
      q = nq; d++;
    }
    this.wave = { start: performance.now(), order: order, max: d, color: color || RED };
  };

  Scene.prototype.verdict = function () {
    var sc = this.surface.scenario, root = this.byId[this.rootId];
    var goal = root ? root.label : "the good state";
    if (this.healed) {
      return {
        linter: { name: sc.linter.name, verdict: "pass", note: sc.linter.note },
        gate: { verdict: "proceed", title: "PROCEED", loop: "loop closed",
                text: (sc.heal && sc.heal.label) || "The way back is proven.", blast: 0 }
      };
    }
    if (!this.action) {
      if (this.gaps > 0) {
        return {
          linter: { name: sc.linter.name, verdict: "idle", note: "" },
          gate: {
            verdict: "warn", title: "GAPS PRESENT", loop: "unproven paths",
            text: this.gaps + " scanned resource" + (this.gaps === 1 ? " has" : "s have") +
              " no directed path back to " + goal + ". Run the risky change or click a marked node for the missing proof.",
            blast: this.gaps
          }
        };
      }
      return {
        linter: { name: sc.linter.name, verdict: "idle", note: "" },
        gate: { verdict: "idle", title: "READY", loop: "loop closed",
                text: "Every change has a proven way back to " + goal + ". Click any node to cut it.", blast: 0 }
      };
    }
    var actLabel = this.byId[this.action] ? this.byId[this.action].label : this.action;
    var isScenario = this.action === sc.actionNode;
    var nodeFix = this.byId[this.action] ? this.byId[this.action].fix : null;
    var fix = nodeFix || (isScenario ? sc.fix : null);
    if (this.blocked) {
      return {
        linter: { name: sc.linter.name, verdict: "pass", note: sc.linter.note },
        gate: {
          verdict: "block", title: "BLOCK", loop: "no path back",
          text: isScenario ? sc.gate.missingProof
              : ("Cutting " + actLabel + " leaves no directed path back to " + goal + "."),
          blast: this.blast, fix: fix
        }
      };
    }
    return {
      linter: { name: sc.linter.name, verdict: "pass", note: sc.linter.note },
      gate: { verdict: "warn", title: "RECOVERABLE", loop: "loop still closed",
              text: actLabel + " is not on a sole way back; the loop still closes another way.", blast: 0 }
    };
  };

  // ---- projection + render ------------------------------------------------
  Scene.prototype._project = function (p, w, h) {
    var cy = Math.cos(this.yaw), sy = Math.sin(this.yaw), cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
    var x1 = p.x * cy - p.z * sy, z1 = p.x * sy + p.z * cy, y1 = p.y;
    var y2 = y1 * cp - z1 * sp, z2 = y1 * sp + z1 * cp;
    var F = 480, scale = F / (F + z2), zoom = Math.min(w, h) / 360;
    return { x: w / 2 + x1 * scale * zoom, y: h / 2 + y2 * scale * zoom, z: z2, s: scale };
  };

  Scene.prototype._screen = function (world, w, h, cam) {
    var b = this._project(world, w, h);
    return {
      x: w / 2 + (b.x - w / 2) * cam.s + cam.x,
      y: h / 2 + (b.y - h / 2) * cam.s + cam.y,
      z: b.z, s: b.s * cam.s
    };
  };

  // Frame all nodes with padding -- the initial view and the reset/refit target.
  Scene.prototype._fit = function (base, w, h) {
    var ids = Object.keys(base);
    if (!ids.length) { return { x: 0, y: 0, s: 1 }; }
    var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity, i, b, nd, mx, my;
    for (i = 0; i < ids.length; i++) {
      b = base[ids[i]];
      nd = this.byId[ids[i]] || {};
      mx = Math.min(170, 42 + String(nd.label || ids[i]).length * 3.8);
      my = nd.sub ? 56 : 38;
      if (b.x - mx < x0) x0 = b.x - mx; if (b.x + mx > x1) x1 = b.x + mx;
      if (b.y - my < y0) y0 = b.y - my; if (b.y + my > y1) y1 = b.y + my;
    }
    var present = {}, fnd;
    for (i = 0; i < ids.length; i++) {
      fnd = this.byId[ids[i]];
      if (fnd) { present[fnd.group || "github"] = true; }
    }
    for (var gk in GROUPS) {
      if (!present[gk]) { continue; }
      var g = GROUPS[gk];
      var corners = [
        this._project({ x: g.x - g.w / 2, y: g.y - g.h / 2, z: g.z || 0 }, w, h),
        this._project({ x: g.x + g.w / 2, y: g.y + g.h / 2, z: g.z || 0 }, w, h)
      ];
      if (corners[0].x < x0) x0 = corners[0].x; if (corners[1].x > x1) x1 = corners[1].x;
      if (corners[0].y < y0) y0 = corners[0].y; if (corners[1].y > y1) y1 = corners[1].y;
    }
    var padX = 46, padT = w < 560 ? 126 : 88, padB = w < 560 ? 68 : 50;
    var bw = Math.max(1, x1 - x0), bh = Math.max(1, y1 - y0);
    var s = Math.min((w - 2 * padX) / bw, (h - padT - padB) / bh, 1.28);
    var cx = (x0 + x1) / 2, cy = (y0 + y1) / 2, regionCy = (padT + (h - padB)) / 2;
    return { s: s, x: -(cx - w / 2) * s, y: (regionCy - h / 2) - (cy - h / 2) * s };
  };

  // Pan so node `id` sits at the canvas centre and zooms to an inspection scale.
  Scene.prototype._center = function (base, id, w, h, s) {
    var b = base[id];
    if (!b) { return null; }
    var target = Math.min(w, h) < 520 ? 0.78 : 0.96;
    return { s: target, x: -(b.x - w / 2) * target, y: -(b.y - h / 2) * target };
  };

  // Free camera: fit once, then the user pans (drag) and zooms (wheel) freely.
  // A click, reset, or surface switch sets a transient eased target (centre / refit).
  Scene.prototype._camera = function (base, w, h) {
    if (!this.cam) { this.cam = this._fit(base, w, h); return; }
    if (this._needFit) { this.camTo = this._fit(base, w, h); this._needFit = false; }
    if (this._focusReq) { this.camTo = this._center(base, this._focusReq, w, h, this.cam.s) || this.camTo; this._focusReq = null; }
    var t = this.camTo;
    if (!t) { return; }                                  // nothing pending -> fully free
    var e = this.reduced ? 1 : 0.16;
    this.cam.x += (t.x - this.cam.x) * e;
    this.cam.y += (t.y - this.cam.y) * e;
    this.cam.s += (t.s - this.cam.s) * e;
    if (Math.abs(t.x - this.cam.x) < 0.5 && Math.abs(t.y - this.cam.y) < 0.5 && Math.abs(t.s - this.cam.s) < 0.003) {
      this.cam.x = t.x; this.cam.y = t.y; this.cam.s = t.s; this.camTo = null;
    }
  };

  Scene.prototype.render = function () {
    var ctx = this.ctx, c = this.canvas;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var w = c.clientWidth, h = c.clientHeight;
    if (c.width !== w * dpr || c.height !== h * dpr) { c.width = w * dpr; c.height = h * dpr; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
    var now = performance.now(), t = (now - this.t0) / 1000;
    if (this.autorot && !this.dragging) this.yaw += 0.0022;

    var self = this;
    var live = this.nodes.filter(function (n) { return !n._hidden && (!self.filter || (n.group || "github") === self.filter); });
    var base = {}, proj = {}, i;
    for (i = 0; i < live.length; i++) base[live[i].id] = this._project(live[i]._p, w, h);
    this._camera(base, w, h);
    var cam = this.cam || { x: 0, y: 0, s: 1 };
    for (i = 0; i < live.length; i++) {
      var _b = base[live[i].id];
      proj[live[i].id] = {
        x: w / 2 + (_b.x - w / 2) * cam.s + cam.x,
        y: h / 2 + (_b.y - h / 2) * cam.s + cam.y,
        z: _b.z, s: _b.s * cam.s
      };
    }

    var wprog = -1;
    if (this.wave) { wprog = (now - this.wave.start) / 1000 / 0.4; if (wprog > this.wave.max + 1.6) this.wave = null; }

    this._clusterBands(ctx, w, h, cam);

    // edges (depth sorted)
    var ed = this.edges.filter(function (e) { return e._a && e._b && proj[e.from] && proj[e.to]; });
    ed.sort(function (a, b) { return (proj[b.from].z + proj[b.to].z) - (proj[a.from].z + proj[a.to].z); });
    for (i = 0; i < ed.length; i++) this._edge(ctx, ed[i], proj, t);

    // nodes (far to near)
    var ord = live.slice().sort(function (a, b) { return proj[b.id].z - proj[a.id].z; });
    for (i = 0; i < ord.length; i++) this._node(ctx, ord[i], proj[ord[i].id], t, wprog);
    this._proj = proj;
  };

  Scene.prototype._clusterBands = function (ctx, w, h, cam) {
    var g, meta, a, b, nn, z, present = {};
    for (z = 0; z < this.nodes.length; z++) {
      nn = this.nodes[z];
      if (!nn._hidden && (!this.filter || (nn.group || "github") === this.filter)) { present[nn.group || "github"] = true; }
    }
    ctx.save();
    for (g in GROUPS) {
      if (!present[g]) { continue; }
      meta = GROUPS[g];
      a = this._screen({ x: meta.x - meta.w / 2, y: meta.y - meta.h / 2, z: meta.z || 0 }, w, h, cam);
      b = this._screen({ x: meta.x + meta.w / 2, y: meta.y + meta.h / 2, z: meta.z || 0 }, w, h, cam);
      var x = Math.min(a.x, b.x), y = Math.min(a.y, b.y);
      var ww = Math.abs(b.x - a.x), hh = Math.abs(b.y - a.y);
      ctx.fillStyle = hexA(meta.color, 0.052); ctx.strokeStyle = hexA(meta.color, 0.34);
      ctx.lineWidth = 1.2; roundRect(ctx, x, y, ww, hh, 10); ctx.fill(); ctx.stroke();
      ctx.fillStyle = "rgba(8,9,14,0.78)";
      roundRect(ctx, x + 7, y + 4, Math.min(190, 12 + meta.label.length * 6.2), 20, 6); ctx.fill();
      ctx.font = "800 10.5px ui-monospace, SFMono-Regular, Menlo, monospace";
      ctx.textAlign = "left"; ctx.fillStyle = hexA(meta.color, 0.88);
      ctx.fillText(meta.label, x + 13, y + 18);
    }
    ctx.restore();
  };

  Scene.prototype._edge = function (ctx, e, proj, t) {
    var pa = proj[e.from], pb = proj[e.to], s = Math.max(pa.s, pb.s);
    var dead = (this.action === e.from || this.action === e.to);
    var onLoop = this.cur && this.cur.from[e.from] && this.cur.to[e.to] && !dead;
    var focus = this.spotlight || this.hover;
    var hot = focus && (focus === e.from || focus === e.to);
    var mx = (pa.x + pb.x) / 2, my = (pa.y + pb.y) / 2 - 9 * s;
    ctx.save();
    if (dead) {
      // severed return arc: draw the broken stub + a "no path back" gap
      ctx.strokeStyle = RED; ctx.globalAlpha = 0.9; ctx.lineWidth = 1.7 * s; ctx.setLineDash([4, 5]);
      ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.quadraticCurveTo(mx, my, pb.x, pb.y); ctx.stroke();
      ctx.setLineDash([]); ctx.globalAlpha = 1;
      ctx.fillStyle = RED; ctx.beginPath(); ctx.arc(mx, my, 2.2 * s, 0, 7); ctx.fill();
    } else if (onLoop) {
      // the way back: Restore Gap brand flow toward the good state
      var col = this.healed ? GREEN : WAYBACK;
      ctx.strokeStyle = col; ctx.globalAlpha = hot ? 0.95 : 0.78; ctx.lineWidth = 1.5 * s;
      ctx.setLineDash([6, 7]); ctx.lineDashOffset = -((t * 26) % 13);
      ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.quadraticCurveTo(mx, my, pb.x, pb.y); ctx.stroke();
      ctx.setLineDash([]);
    } else {
      var stranded = this.states[e.from] === "stranded" || this.states[e.to] === "stranded" ||
                     this.states[e.from] === "gap" || this.states[e.to] === "gap";
      ctx.strokeStyle = hot ? "rgba(183,148,255,0.85)" : stranded ? "rgba(255,96,118,0.55)" : "rgba(139,140,180,0.32)";
      ctx.globalAlpha = 0.7; ctx.lineWidth = 1.1 * s;
      ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.quadraticCurveTo(mx, my, pb.x, pb.y); ctx.stroke();
    }
    // arrowhead at the target end (direction of recovery flow)
    if (!dead) {
      var ang = Math.atan2(pb.y - my, pb.x - mx), r = (this.byId[e.to].root ? 17 : 9) * pb.s + 3;
      var ax = pb.x - Math.cos(ang) * r, ay = pb.y - Math.sin(ang) * r, ah = 5 * s;
      ctx.fillStyle = onLoop ? (this.healed ? GREEN : WAYBACK) : "rgba(160,170,190,0.5)";
      ctx.globalAlpha = 0.9; ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(ax - Math.cos(ang - 0.42) * ah, ay - Math.sin(ang - 0.42) * ah);
      ctx.lineTo(ax - Math.cos(ang + 0.42) * ah, ay - Math.sin(ang + 0.42) * ah);
      ctx.closePath(); ctx.fill();
    }
    ctx.restore();
  };

  Scene.prototype._node = function (ctx, nd, p, t, wprog) {
    var st = this.states[nd.id], base = PALETTE[nd.kind] || PALETTE.generic;
    var pulse = (st === "stranded" || st === "gap" || st === "dead") ? (Math.sin(t * 4) * 0.5 + 0.5) : 0;
    var passed = this.wave && this.wave.order[nd.id] !== undefined && wprog >= this.wave.order[nd.id];
    var rad = (nd.root ? 17 : 9) * p.s + (nd.root ? 2 : 0);
    var depth = Math.max(0.25, Math.min(1, p.s));
    var glowCol = st === "stranded" || st === "gap" || st === "dead" ? RED :
                  (nd.root && this.action) ? WAYBACK : base;
    var glowR = rad * (st === "ok" || st === "root" ? 2.4 : 3.3 + pulse * 1.2);
    var grd = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, glowR);
    grd.addColorStop(0, hexA(glowCol, 0.42 * depth + (passed ? 0.3 : 0)));
    grd.addColorStop(1, hexA(glowCol, 0));
    ctx.fillStyle = grd; ctx.beginPath(); ctx.arc(p.x, p.y, glowR, 0, 7); ctx.fill();
    if (this.spotlight === nd.id) {
      var spot = st === "dead" || st === "gap" || st === "stranded" ? RED : this.healed ? GREEN : WAYBACK;
      ctx.save();
      ctx.strokeStyle = hexA(spot, 0.95);
      ctx.lineWidth = Math.max(1.5, 2.4 * p.s);
      ctx.setLineDash([5 * p.s, 5 * p.s]);
      ctx.beginPath(); ctx.arc(p.x, p.y, rad + 7 * p.s, 0, 7); ctx.stroke();
      ctx.restore();
    }

    if (nd.root) {
      var broken = this.action && this.blocked;
      var col = broken ? RED : (this.action ? WAYBACK : "#eef1f7");
      ctx.save(); ctx.translate(p.x, p.y);
      ctx.strokeStyle = col; ctx.lineWidth = 3.4 * p.s; ctx.lineCap = "round";
      ctx.beginPath(); ctx.arc(0, 0, rad, Math.PI * 0.28, Math.PI * 1.72); ctx.stroke();
      ctx.fillStyle = broken ? RED : (this.action ? WAYBACK : BRAND);
      ctx.fillRect(rad * 0.2, -rad * 0.22, rad * 0.95, rad * 0.44);
      ctx.restore();
    } else {
      var fill = st === "stranded" || st === "gap" ? RED : st === "dead" ? "#7a1020" : base;
      var ring = st === "stranded" || st === "gap" || st === "dead" ? RED : base;
      ctx.beginPath(); ctx.arc(p.x, p.y, rad, 0, 7);
      ctx.fillStyle = hexA(fill, 0.16 + 0.5 * depth); ctx.fill();
      ctx.lineWidth = ((this.spotlight === nd.id || this.hover === nd.id) ? 2.4 : 1.6) * p.s;
      ctx.strokeStyle = hexA(ring, 0.55 + 0.45 * depth); ctx.stroke();
      if (st === "dead") {
        ctx.strokeStyle = RED; ctx.lineWidth = 2 * p.s;
        ctx.beginPath();
        ctx.moveTo(p.x - rad * .5, p.y - rad * .5); ctx.lineTo(p.x + rad * .5, p.y + rad * .5);
        ctx.moveTo(p.x + rad * .5, p.y - rad * .5); ctx.lineTo(p.x - rad * .5, p.y + rad * .5); ctx.stroke();
      }
      // real-finding marker: a small amber dot says "click for the fix"
      if (nd.fix && st !== "dead") {
        ctx.fillStyle = st === "gap" || st === "stranded" ? RED : AMBER; ctx.globalAlpha = 0.95;
        ctx.beginPath(); ctx.arc(p.x + rad * 0.82, p.y - rad * 0.82, 2.7 * p.s, 0, 7); ctx.fill();
        ctx.globalAlpha = 1;
      }
    }

    var compact = this.canvas.clientWidth < 520;
    var keyLabel = nd.root || nd.kind === "org" ||
      st === "dead" || this.spotlight === nd.id || this.hover === nd.id;
    var labelThreshold = compact ? 0.70 : 0.58;
    if (p.s > labelThreshold || keyLabel || this.hover === nd.id) {
      var lab = nd.label, fs = Math.round((nd.root ? 12.5 : 11) * Math.max(0.78, p.s));
      ctx.font = "700 " + fs + "px ui-monospace, SFMono-Regular, Menlo, monospace";
      var tw = ctx.measureText(lab).width, ly = p.y + rad + fs + 3;
      ctx.globalAlpha = 0.5 + 0.5 * depth; ctx.fillStyle = "rgba(8,9,14,0.74)";
      roundRect(ctx, p.x - tw / 2 - 6, ly - fs - 1, tw + 12, fs + 7, 5); ctx.fill();
      ctx.globalAlpha = 1;
      ctx.fillStyle = st === "stranded" || st === "gap" || st === "dead" ? "#ffd2d8" : "#dfe6f2";
      ctx.textAlign = "center"; ctx.fillText(lab, p.x, ly - 1);
      if (nd.sub && (p.s > 0.64 || nd.root || this.spotlight === nd.id || this.hover === nd.id)) {
        ctx.font = "600 " + (fs - 2) + "px ui-sans-serif, system-ui, sans-serif";
        ctx.fillStyle = "rgba(163,173,191,0.85)"; ctx.fillText(nd.sub, p.x, ly + fs + 1);
      }
    }
  };

  // ---- interaction --------------------------------------------------------
  Scene.prototype._bind = function () {
    var self = this, c = this.canvas, last = null;
    function pos(ev) { var r = c.getBoundingClientRect(); var e = ev.touches ? ev.touches[0] : ev; return { x: e.clientX - r.left, y: e.clientY - r.top }; }
    function pick(pt) {
      if (!self._proj) return null; var best = null, bd = 22 * 22;
      for (var id in self._proj) { var p = self._proj[id]; var dx = p.x - pt.x, dy = p.y - pt.y, d = dx * dx + dy * dy; if (d < bd) { bd = d; best = id; } }
      return best;
    }
    c.addEventListener("pointerdown", function (ev) { self.dragging = true; last = pos(ev); self._moved = false; c.style.cursor = "grabbing"; c.setPointerCapture(ev.pointerId); });
    c.addEventListener("pointermove", function (ev) {
      var p = pos(ev);
      if (self.dragging && last && self.cam) {
        var dx = p.x - last.x, dy = p.y - last.y; if (Math.abs(dx) + Math.abs(dy) > 3) self._moved = true;
        self.cam.x += dx; self.cam.y += dy; self.camTo = null; self._focusReq = null; last = p;   // free pan
      } else { var hit = pick(p); self.hover = hit; c.style.cursor = hit ? "pointer" : "grab"; }
    });
    function up(ev) {
      if (self.dragging && !self._moved) {
        var hit = pick(pos(ev));
        if (hit && hit !== self.rootId && !self.byId[hit]._hidden) { self._focusReq = hit; self.simulate(hit); }  // center + cut
      }
      self.dragging = false; last = null; c.style.cursor = "grab";
    }
    c.addEventListener("pointerup", up);
    c.addEventListener("pointerleave", function () { self.dragging = false; self.hover = null; });
    c.addEventListener("wheel", function (ev) {
      if (!self.cam) { return; }
      ev.preventDefault();
      var p = pos(ev), w = c.clientWidth, h = c.clientHeight, s = self.cam.s;
      var ns = Math.max(0.24, Math.min(4.5, s * Math.exp(-ev.deltaY * 0.0015))), k = ns / s;
      var dpx = p.x - w / 2, dpy = p.y - h / 2;
      self.cam.x = dpx - (dpx - self.cam.x) * k;          // zoom toward the cursor
      self.cam.y = dpy - (dpy - self.cam.y) * k;
      self.cam.s = ns; self.camTo = null; self._focusReq = null;
    }, { passive: false });
  };

  // ---- mount + chrome -----------------------------------------------------
  function mount(root, spec) {
    if (typeof root === "string") root = document.getElementById(root) || document.querySelector(root);
    if (!root) return;
    var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    root.classList.add("rg-graph");
    root.innerHTML =
      '<div class="rg-examples"><div class="rg-examples-head"><b>Three use cases</b><span>real commands, public-safe references</span></div>' +
        '<div class="rg-tabs"></div></div>' +
      '<div class="rg-surface">' +
        '<div class="rg-map"><div class="rg-filters"></div>' +
          '<div class="rg-stage"><canvas class="rg-canvas"></canvas>' +
            '<div class="rg-legend"></div><div class="rg-action"></div></div></div>' +
        '<div class="rg-side"><div class="rg-usecase"></div><div class="rg-artifact"></div>' +
          '<div class="rg-flow" aria-label="How Restore Gap evaluates this change"></div>' +
          '<div class="rg-flow-detail" aria-live="polite"></div>' +
          '<div class="rg-panel"><div class="rg-panel-title"><b>Gate result</b><span>checked evidence, not agent claims</span></div><div class="rg-verdicts"></div><div class="rg-controls"></div></div></div>' +
      '</div>';

    var tabsEl = root.querySelector(".rg-tabs"), actionEl = root.querySelector(".rg-action");
    var usecaseEl = root.querySelector(".rg-usecase");
    var artifactEl = root.querySelector(".rg-artifact");
    var flowEl = root.querySelector(".rg-flow");
    var flowDetailEl = root.querySelector(".rg-flow-detail");
    var verdictsEl = root.querySelector(".rg-verdicts"), controlsEl = root.querySelector(".rg-controls");
    root.querySelector(".rg-legend").innerHTML =
      '<span><i class="d ok"></i>way back</span>' +
      '<span><i class="d proof"></i>proof</span>' +
      '<span><i class="d str"></i>gap</span>' +
      '<span><i class="d inv"></i>source</span>';

    var scene = new Scene(root, spec.surfaces[spec.activeSurface || 0], reduced);
    root.__rgScene = scene;
    var activeFlow = "gate";

    var filtersEl = root.querySelector(".rg-filters");
    filtersEl.innerHTML =
      filterChip("", "All layers") + filterChip("github", "GitHub") + filterChip("terraform", "Terraform") +
      filterChip("cloud", "Cloud") + filterChip("vendor", "Vendor") + filterChip("offline", "Offline") +
      filterChip("device", "Device");
    function syncFilters() {
      var present = scene.groupsPresent(), btns = filtersEl.querySelectorAll(".rg-filter"), k, group, active, disabled;
      if (scene.filter && !present[scene.filter]) { scene.setFilter(""); }
      active = scene.filter || "";
      for (k = 0; k < btns.length; k++) {
        group = btns[k].getAttribute("data-g");
        disabled = !!group && !present[group];
        btns[k].disabled = disabled;
        btns[k].className = "rg-filter" + (active === group ? " on" : "") + (disabled ? " off" : "");
        btns[k].setAttribute("aria-pressed", active === group ? "true" : "false");
      }
    }
    filtersEl.addEventListener("click", function (ev) {
      var b = ev.target && ev.target.closest ? ev.target.closest(".rg-filter") : null;
      if (!b || b.disabled) { return; }
      scene.setFilter(b.getAttribute("data-g"));
      syncFilters();
    });
    syncFilters();

    function renderTabs() {
      tabsEl.innerHTML = "";
      if (spec.surfaces.length <= 1) {
        var src = scene.surface.source;
        if (src) {
          var chip = document.createElement("div");
          chip.className = "rg-source";
          chip.innerHTML = '<span class="rg-dot"></span><b>real ' + esc(src.tool || "restoregap") +
            " run</b>" + (src.org ? " · " + esc(src.org) : "") +
            (src.findings != null ? " · " + esc(src.findings) + " findings" : "") +
            (src.note ? '<span class="rg-src-note">' + esc(src.note) + "</span>" : "");
          tabsEl.appendChild(chip);
        }
        return;
      }
      spec.surfaces.forEach(function (s) {
        var b = document.createElement("button");
        b.className = "rg-tab" + (s === scene.surface ? " on" : "");
        b.innerHTML = "<b>" + esc(s.label) + "</b><span>" + esc(s.tagline || "") + "</span>";
        b.onclick = function () { activeFlow = "gate"; scene.setSurface(s); scene.wave = null; guideStep("gate"); };
        tabsEl.appendChild(b);
      });
    }
    function renderUsecase() {
      var s = scene.surface, src = s.source || {};
      var meta = [];
      var verdict = scene.verdict().gate.verdict || "idle";
      var resultText = scene.healed ? "PROCEED" : String(verdict).toUpperCase();
      var resultClass = scene.healed || verdict === "proceed" || verdict === "pass" ? "pass" :
        (verdict === "block" ? "block" : (verdict === "warn" ? "warn" : ""));
      if (src.scanId) meta.push("scan " + esc(src.scanId));
      if (src.findings != null) meta.push(esc(src.findings) + " finding" + (Number(src.findings) === 1 ? "" : "s"));
      usecaseEl.innerHTML =
        '<div class="rg-use-main"><span class="rg-use-k">Use case</span><b>' + esc(s.label) + '</b><p>' + esc(s.summary || s.tagline || "") + '</p></div>' +
        '<div class="rg-use-facts">' +
          '<div class="rg-use-fact"><span>Gate</span><strong class="rg-use-result ' + resultClass + '">Gate: ' + esc(resultText) + '</strong></div>' +
          '<div class="rg-use-fact"><span>Source</span><code>' + esc(src.org || src.tool || "restoregap") + '</code></div>' +
          (meta.length ? '<div class="rg-use-fact"><span>Scan</span><small>' + meta.join(" · ") + '</small></div>' : "") +
        '</div>';
    }
    function renderArtifact() {
      var a = scene.surface.artifact || {}, items = a.items || [];
      if (!items.length) { artifactEl.innerHTML = ""; return; }
      artifactEl.innerHTML =
        '<div class="rg-artifact-head"><b>' + esc(a.title || "Actual input") + '</b>' +
        (a.note ? '<span>' + esc(a.note) + '</span>' : '') + '</div>' +
        '<div class="rg-artifact-grid">' + items.map(function (item) {
          return '<div class="rg-artifact-item"><span>' + esc(item.label || "Input") +
            '</span><pre><code>' + esc(item.code || "") + '</code></pre></div>';
        }).join("") + '</div>';
    }
    function actionNodeId() { return scene.surface.scenario.actionNode; }
    function proofNodeId() {
      var heal = scene.surface.scenario.heal || {};
      return heal.revealNodes && heal.revealNodes.length ? heal.revealNodes[0] : scene.rootId;
    }
    function guideStep(step) {
      var actionId = actionNodeId(), proofId = proofNodeId();
      activeFlow = step || activeFlow;
      if (activeFlow === "input") {
        scene.reset(); scene.focusNode(actionId);
      } else if (activeFlow === "map") {
        scene.reset(); scene.refit();
      } else if (activeFlow === "check") {
        scene.reset(); scene.focusNode(actionId);
      } else if (activeFlow === "gate") {
        if (!scene.action || scene.healed || scene.action !== actionId) scene.simulate(actionId);
        scene.refit();
      } else if (activeFlow === "proof") {
        if (!scene.action || scene.action !== actionId) scene.simulate(actionId);
        if (!scene.healed) scene.heal();
        scene.focusNode(proofId);
      }
      renderAll();
    }
    function flowItems() {
      var s = scene.surface, v = scene.verdict(), f = s.flow || {};
      var flowCode = s.flowCode || {}, flowDetail = s.flowDetail || {};
      var gateState = scene.healed ? "pass" : (v.gate.verdict === "block" ? "block" : (v.gate.verdict === "warn" ? "warn" : "idle"));
      var gateText = scene.healed ? "proof accepted; loop closed" :
        (f.gate || (scene.action ? "block if the way back is missing" : "gate the change before it runs"));
      return [
        { key: "input", k: "Input", text: f.input || "scan, diff, or local intent", cls: "done",
          detail: flowDetail.input || "Restore Gap starts from declared change input plus observed state: a scan DB and PR diff, a local intent file and context, or a read-only audit packet.",
          code: flowCode.input || "src/restoregap/cli.py" },
        { key: "map", k: "Map", text: f.map || "recovery path from real sources", cls: "done",
          detail: flowDetail.map || "The tool resolves affected files, workflows, resources, runbooks, and proof records into a directed recovery graph with source references.",
          code: flowCode.map || "src/restoregap/report/recovery_graph.py" },
        { key: "check", k: "Check", text: f.change || "normal checks can still pass", cls: scene.action || scene.healed ? "pass" : "idle",
          detail: flowDetail.check || "Normal checks can pass. Restore Gap separately checks whether the changed node still has a directed path back to the known-good state.",
          code: flowCode.check || "src/restoregap/preflight.py" },
        { key: "gate", k: "Gate", text: gateText, cls: gateState,
          detail: flowDetail.gate || "The gate returns proceed only when the way-back loop remains closed. If a required path or proof is missing, it blocks and names the missing evidence.",
          code: flowCode.gate || "src/restoregap/preflight.py" },
        { key: "proof", k: "Proof", text: scene.healed ? (f.proven || "loop closed by evidence") : (f.proof || "required evidence names the way back"), cls: scene.healed ? "pass" : "idle",
          detail: flowDetail.proof || "Proof is evidence Restore Gap can inspect for the active surface: source references and open findings for PR/audit, plus timestamp, hash, verifier, host, and signature checks for local proof records.",
          code: flowCode.proof || "src/restoregap/adapters/local/context_validation.py" }
      ];
    }
    function renderFlow() {
      var items = flowItems();
      flowEl.innerHTML = items.map(function (it, idx) {
        return '<button type="button" class="rg-flow-step ' + it.cls + (activeFlow === it.key ? " active" : "") +
          '" data-step="' + esc(it.key) + '" aria-pressed="' + (activeFlow === it.key ? "true" : "false") +
          '" aria-label="Step ' + (idx + 1) + ': ' + esc(it.k) + ' - ' + esc(it.text) + '">' +
          '<span class="rg-flow-n">' + (idx + 1) + '</span><div><b>' + esc(it.k) +
          '</b><p>' + esc(it.text) + '</p></div></button>';
      }).join("");
      renderFlowDetail(items);
    }
    function renderFlowDetail(items) {
      var selected = items.find(function (it) { return it.key === activeFlow; }) || items[0];
      flowDetailEl.innerHTML =
        '<b>' + esc(selected.k) + '</b><p>' + esc(selected.detail) + '</p>' +
        '<span>Real code</span><code>' + esc(selected.code) + '</code>';
    }
    function renderPanel() {
      var sc = scene.surface.scenario, v = scene.verdict();
      var selected = activeFlow === "proof" && scene.healed
        ? scene.byId[proofNodeId()]
        : (scene.action ? scene.byId[scene.action] : scene.byId[sc.actionNode]);
      actionEl.innerHTML =
        '<div class="rg-act-pill">Evaluating change</div>' +
        '<div class="rg-act-lbl">' + esc(sc.actionLabel) + '</div>';
      verdictsEl.innerHTML =
        verdictRow(v.linter.name, v.linter.verdict, v.linter.verdict === "pass" ? "exit 0 · no failed checks" : "watching", v.linter.note, null) +
        verdictRow("Restore Gap", v.gate.verdict, v.gate.title, v.gate.text, v.gate) +
        (v.gate.fix ? fixRow(v.gate.fix) : "") +
        (selected ? sourceRow(selected) : "");
      controlsEl.innerHTML = "";
      var run = ctlBtn(scene.action ? "Evaluate again" : "Evaluate this change", "primary");
      run.onclick = function () { activeFlow = "gate"; scene.simulate(sc.actionNode); scene.refit(); renderAll(); };
      controlsEl.appendChild(run);
      if (scene.action && !scene.healed) {
        var heal = ctlBtn("Prove the way back", "heal");
        heal.onclick = function () { activeFlow = "proof"; scene.heal(); scene.focusNode(proofNodeId()); renderAll(); };
        controlsEl.appendChild(heal);
      }
      if (scene.action) {
        var rst = ctlBtn("Reset", "ghost"); rst.onclick = function () { activeFlow = "map"; scene.reset(); renderAll(); };
        controlsEl.appendChild(rst);
      }
    }
    function renderAll() { renderTabs(); syncFilters(); renderUsecase(); renderArtifact(); renderFlow(); renderPanel(); }
    scene.onChange = function () { renderFlow(); renderPanel(); };
    guideStep("gate");
    flowEl.addEventListener("click", function (ev) {
      var b = ev.target && ev.target.closest ? ev.target.closest(".rg-flow-step") : null;
      if (!b) { return; }
      guideStep(b.getAttribute("data-step") || activeFlow);
    });

    function frame() { scene.render(); requestAnimationFrame(frame); }
    requestAnimationFrame(frame);
    return scene;
  }

  function filterChip(group, label) {
    var g = GROUPS[group] || { color: BRAND };
    return '<button type="button" class="rg-filter" data-g="' + esc(group) + '" style="--c:' + esc(g.color) + '">' + esc(label) + '</button>';
  }

  function verdictRow(name, verdict, title, text, gate) {
    var cls = verdict === "block" ? "block" : (verdict === "proceed" || verdict === "pass") ? "pass" : verdict === "warn" ? "warn" : "idle";
    var icon = verdict === "block" ? "✕" : (verdict === "proceed" || verdict === "pass") ? "✓" : verdict === "warn" ? "!" : "·";
    var loop = gate && gate.loop ? '<span class="rg-loop ' + cls + '">' + esc(gate.loop) + '</span>' : "";
    var blast = gate && gate.blast ? '<span class="rg-blast">' + gate.blast + ' with no way back</span>' : "";
    return '<div class="rg-vrow ' + cls + (gate ? " gate" : "") + '">' +
      '<span class="rg-vic">' + icon + '</span>' +
      '<div class="rg-vbody"><div class="rg-vhead"><b>' + esc(name) + '</b>' +
      '<span class="rg-vtag">' + esc(title) + '</span>' + loop + blast + '</div>' +
      (text ? '<div class="rg-vtext">' + esc(text) + '</div>' : '') + '</div></div>';
  }

  function fixRow(fix) {
    var doc = fix.doc
      ? '<a class="rg-fix-doc" href="' + esc(fix.doc) + '" target="_blank" rel="noopener">' +
        esc(fix.docLabel || "view the fix") + " &rarr;</a>"
      : (fix.docLabel ? '<span class="rg-fix-doc">' + esc(fix.docLabel) + "</span>" : "");
    return '<div class="rg-vrow fixrow"><span class="rg-vic fix">&#10003;</span>' +
      '<div class="rg-vbody"><div class="rg-vhead"><b>Required proof</b>' +
      (fix.severity ? '<span class="rg-vtag">' + esc(fix.severity) + "</span>" : "") +
      (fix.gap ? '<span class="rg-gapid">' + esc(fix.gap) + "</span>" : "") + "</div>" +
      (fix.fix ? '<div class="rg-vtext">' + esc(fix.fix) + "</div>" : "") +
      (doc ? '<div class="rg-vtext">' + doc + "</div>" : "") + "</div></div>";
  }

  function sourceRow(nd) {
    var links = [];
    if (nd.source) links.push(refLink(nd.source));
    if (nd.refs && nd.refs.length) {
      for (var i = 0; i < nd.refs.length; i++) links.push(refLink(nd.refs[i]));
    }
    var sourceLabel = nd.source && nd.source.label ? nd.source.label : nd.label;
    var summary = '<div class="rg-vtext"><b>' + esc(sourceLabel) + '</b>' +
      (nd.sub ? ' <span class="rg-muted-inline">' + esc(nd.sub) + '</span>' : '') + '</div>';
    var body = links.length
      ? '<div class="rg-source-links">' + links.join("") + '</div>'
      : '<div class="rg-vtext">Observed in the Restore Gap packet for this scan.</div>';
    return '<details class="rg-vrow sourcerow"><summary class="rg-source-summary"><span class="rg-vic src">↗</span>' +
      '<div class="rg-vbody"><div class="rg-vhead"><b>Evidence</b>' +
      (nd.group ? '<span class="rg-nodegroup">' + esc(nd.group) + "</span>" : "") +
      (nd.kind ? '<span class="rg-vtag">' + esc(nd.kind) + "</span>" : "") + "</div>" +
      summary + '</div><span class="rg-openref">source refs</span></summary><div class="rg-source-body">' + body + "</div></details>";
  }

  function refLink(ref) {
    var text = esc(ref.label || ref.url || "source");
    var meta = ref.sha ? '<span class="rg-sha">sha ' + esc(String(ref.sha).slice(0, 10)) + '</span>' : "";
    var detail = ref.detail ? '<span class="rg-ref-detail">' + esc(ref.detail) + '</span>' : "";
    if (ref.url) {
      return '<a class="rg-ref-link" href="' + esc(ref.url) + '" target="_blank" rel="noopener">' +
        text + " →" + meta + detail + "</a>";
    }
    return '<span class="rg-ref-link">' + text + meta + detail + "</span>";
  }

  function ctlBtn(label, kind) { var b = document.createElement("button"); b.className = "rg-btn " + (kind || ""); b.textContent = label; return b; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function hexA(hex, a) {
    if (hex[0] !== "#") return hex;
    var n = parseInt(hex.slice(1), 16); return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
  }
  function roundRect(ctx, x, y, w, h, r) { ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }

  window.RestoreGapGraph = { mount: mount };
})();
