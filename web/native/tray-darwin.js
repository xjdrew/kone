// KONE's own AppKit menu only: no Apple Events, Accessibility or shell commands.
// stdin: bounded newline-delimited state JSON. stdout: READY and action names.
// The Go controller owns every operation; this companion never changes network state.
var koneTrayObjects; // NSMenuItem's target is weak; retain its bridged JS owner.

function normalizeTrayState(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Invalid tray state");
  }
  function text(value, limit) {
    return typeof value === "string"
      ? value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, limit)
      : "";
  }
  return {
    status: text(input.status, 40) || "unknown",
    detail: text(input.detail, 500),
    can_start: input.can_start === true,
    can_pause: input.can_pause === true,
    can_diagnose: input.can_diagnose === true,
  };
}

function run(argv) {
  ObjC.import("Foundation");
  ObjC.import("AppKit");
  ObjC.bindFunction("exit", ["void", ["int"]]);
  ObjC.bindFunction("fcntl", ["int", ["int", "int", "int"]]);
  ObjC.bindFunction("read", ["long", ["int", "void *", "unsigned long"]]);

  var output = $.NSFileHandle.fileHandleWithStandardOutput;
  var errors = $.NSFileHandle.fileHandleWithStandardError;
  function write(handle, text) {
    handle.writeData($(text + "\n").dataUsingEncoding($.NSUTF8StringEncoding));
  }
  var bar;
  var item;
  var flags = -1;
  try {
    // A background/SSH session is not proof that AppKit is unavailable. Ask
    // AppKit itself, without automating other apps or changing OS settings.
    var app = $.NSApplication.sharedApplication;
    app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
    if (Number($.NSScreen.screens.count) === 0) {
      write(errors, "KONE_TRAY_UNAVAILABLE: no WindowServer display");
      $.exit(77);
      return;
    }
    var selfTest = argv.length === 1 && argv[0] === "--self-test";
    if (argv.length && !selfTest) throw new Error("Invalid tray arguments");
    var state = normalizeTrayState({});
    var closing = false;
    var alive = true;
    var emitted = [];
    var entries = {};
    function emit(action) {
      if (closing && action !== "OPEN") return;
      if (action === "START" && !state.can_start) return;
      if (action === "PAUSE" && !state.can_pause) return;
      if (action === "DIAGNOSTICS" && !state.can_diagnose) return;
      if (selfTest) emitted.push(action);
      else write(output, action);
      if (action === "EXIT") {
        closing = true;
        update({ status: "stopping", detail: "正在等待控制层完成清理" });
      }
    }
    ObjC.registerSubclass({
      name: "KoneTrayMenuTarget",
      superclass: "NSObject",
      methods: {
        "open:": {
          types: ["void", ["id"]],
          implementation: function () {
            emit("OPEN");
          },
        },
        "start:": {
          types: ["void", ["id"]],
          implementation: function () {
            emit("START");
          },
        },
        "pause:": {
          types: ["void", ["id"]],
          implementation: function () {
            emit("PAUSE");
          },
        },
        "diagnostics:": {
          types: ["void", ["id"]],
          implementation: function () {
            emit("DIAGNOSTICS");
          },
        },
        "exit:": {
          types: ["void", ["id"]],
          implementation: function () {
            emit("EXIT");
          },
        },
      },
    });
    var target = $.KoneTrayMenuTarget.alloc.init;
    var menu = $.NSMenu.alloc.initWithTitle("KONE");
    menu.autoenablesItems = false;
    function entry(name, title, selector) {
      var value = $.NSMenuItem.alloc.initWithTitleActionKeyEquivalent(
        title,
        selector || "",
        "",
      );
      if (selector) value.target = target;
      else value.enabled = false;
      entries[name] = value;
      menu.addItem(value);
      return value;
    }
    entry("status", "KONE · 状态未知", "");
    menu.addItem($.NSMenuItem.separatorItem);
    entry("open", "打开管理界面", "open:");
    entry("start", "启用接管", "start:");
    entry("pause", "暂停接管", "pause:");
    entry("diagnostics", "打开诊断", "diagnostics:");
    menu.addItem($.NSMenuItem.separatorItem);
    entry("exit", "退出 KONE", "exit:");
    bar = $.NSStatusBar.systemStatusBar;
    item = bar.statusItemWithLength($.NSVariableStatusItemLength);
    if (item.isNil() || item.button.isNil()) {
      write(
        errors,
        "KONE_TRAY_UNAVAILABLE: AppKit could not create a status item",
      );
      $.exit(77);
      return;
    }
    item.menu = menu;
    koneTrayObjects = [target, menu, item];
    function update(input) {
      state = normalizeTrayState(input);
      var labels = {
        running: "已接管",
        paused: "已暂停",
        starting: "启动中",
        stopping: "暂停中",
        failed: "失败",
        degraded: "需处理",
        unknown: "状态未知",
      };
      var label = labels[state.status];
      if (typeof label !== "string") label = state.status;
      item.button.title = "KONE " + (state.status === "running" ? "●" : "○");
      item.button.toolTip =
        "KONE · " + label + (state.detail ? " · " + state.detail : "");
      entries.status.title = "KONE · " + label;
      entries.status.toolTip = state.detail;
      entries.open.enabled = true;
      entries.start.enabled = !closing && state.can_start;
      entries.pause.enabled = !closing && state.can_pause;
      entries.diagnostics.enabled = !closing && state.can_diagnose;
      entries.exit.enabled = !closing;
    }
    update({});
    app.finishLaunching;
    if (selfTest) {
      function check(value) {
        if (!value) throw new Error("AppKit tray self-test failed");
      }
      update({
        status: "paused",
        can_start: true,
        can_pause: false,
        can_diagnose: true,
      });
      check(Boolean(entries.start.enabled) && !Boolean(entries.pause.enabled));
      menu.performActionForItemAtIndex(2); // Actual NSMenu target/action dispatch.
      menu.performActionForItemAtIndex(3);
      target.pause($()); // Disabled operation remains guarded at the callback.
      check(emitted.join(",") === "OPEN,START");
      update({ status: "running", can_pause: true, can_diagnose: true });
      check(!Boolean(entries.start.enabled) && Boolean(entries.pause.enabled));
      menu.performActionForItemAtIndex(4);
      menu.performActionForItemAtIndex(5);
      menu.performActionForItemAtIndex(7);
      check(emitted.join(",") === "OPEN,START,PAUSE,DIAGNOSTICS,EXIT");
      check(!Boolean(entries.exit.enabled) && closing);
      write(output, "SELFTEST_OK");
      return;
    }
    flags = $.fcntl(0, 3, 0); // Darwin F_GETFL/F_SETFL and O_NONBLOCK.
    if (flags < 0 || $.fcntl(0, 4, flags | 4) < 0)
      throw new Error("Tray input is unavailable");
    var pending = $.NSMutableData.data;
    var chunk = $.NSMutableData.dataWithLength(4096);
    function readState() {
      var size = Number($.read(0, chunk.mutableBytes, 4096));
      if (size < 0) return; // Nonblocking pipe has no update yet.
      if (size === 0) {
        alive = false;
        return;
      }
      pending.appendBytesLength(chunk.mutableBytes, size);
      if (Number(pending.length) > 65536)
        throw new Error("Tray state exceeds limit");
      var decoded = $.NSString.alloc.initWithDataEncoding(
        pending,
        $.NSUTF8StringEncoding,
      );
      if (decoded.isNil()) return; // A UTF-8 character can cross pipe reads.
      var lines = ObjC.unwrap(decoded).split("\n");
      var tail = lines.pop();
      pending = $(tail).dataUsingEncoding($.NSUTF8StringEncoding).mutableCopy;
      for (var i = 0; i < lines.length; i++) {
        if (lines[i]) update(JSON.parse(lines[i]));
      }
    }
    write(output, "READY");
    while (alive) {
      var pool = $.NSAutoreleasePool.alloc.init;
      try {
        readState();
        if (!alive) break;
        var event = app.nextEventMatchingMaskUntilDateInModeDequeue(
          $.NSEventMaskAny,
          $.NSDate.dateWithTimeIntervalSinceNow(0.1),
          $.NSDefaultRunLoopMode,
          true,
        );
        if (!event.isNil()) app.sendEvent(event);
        app.updateWindows;
      } finally {
        pool.drain;
      }
    }
  } catch (error) {
    var reason = String(error.message || "native tray failure");
    if (
      /cannot (?:connect|communicate).*WindowServer|WindowServer.*(?:unavailable|connection)|CGSConnection.*(?:fail|invalid)/i.test(
        reason,
      )
    ) {
      write(
        errors,
        "KONE_TRAY_UNAVAILABLE: WindowServer rejected the AppKit connection",
      );
      if (item && bar) bar.removeStatusItem(item);
      $.exit(77);
      return;
    }
    write(errors, "KONE_TRAY_ERROR: " + reason.slice(0, 240));
    if (item && bar) bar.removeStatusItem(item);
    $.exit(1);
  } finally {
    if (flags >= 0) $.fcntl(0, 4, flags);
    if (item && bar) bar.removeStatusItem(item);
    koneTrayObjects = undefined;
  }
}
