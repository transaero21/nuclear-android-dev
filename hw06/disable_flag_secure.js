Java.perform(function () {
  var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
  var FLAG_SECURE = LayoutParams.FLAG_SECURE.value;

  var Window = Java.use('android.view.Window');

  // --- Hook: Window.setFlags(flags, mask)
  var setFlags = Window.setFlags.overload('int', 'int');
  setFlags.implementation = function (flags, mask) {
    if ((flags & FLAG_SECURE) !== 0) {
      console.debug("FLAG_SECURE detected in setFlags - removing");
      flags &= ~FLAG_SECURE;
    }
    return setFlags.call(this, flags, mask);
  };

  // --- Hook: Window.addFlags(flags)
  var addFlags = Window.addFlags.overload('int');
  addFlags.implementation = function (flags) {
    if ((flags & FLAG_SECURE) !== 0) {
      console.debug("FLAG_SECURE detected in addFlags - removing");
      flags &= ~FLAG_SECURE;
    }
    return addFlags.call(this, flags);
  };

  // --- Hook: Window.setAttributes(attrs)
  var setAttributes = Window.setAttributes.overload('android.view.WindowManager$LayoutParams');
  setAttributes.implementation = function (attrs) {
    if ((attrs.flags & FLAG_SECURE) !== 0) {
      console.debug("FLAG_SECURE detected in setAttributes - removing");
      attrs.flags &= ~FLAG_SECURE;
    }
    return setAttributes.call(this, attrs);
  };

    
  var SurfaceView = Java.use('android.view.SurfaceView');

  // --- Hook: SurfaceView.setSecure(boolean)
  var setSecure = SurfaceView.setSecure.overload('boolean');
  setSecure.implementation = function (secure) {
    console.debug("SurfaceView.setSecure(" + secure + ") called - ignoring");
    return setSecure.call(this, false);
  };


  var WindowManager = Java.use('android.view.WindowManagerImpl');

  // --- Hook: WindowManager.addView(View view, ViewGroup.LayoutParams params)
  var addView = WindowManager.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams');
  addView.implementation = function (view, params) {
    try {
      var viewClass = view.getClass().getName();
      var paramFlags = Java.cast(params, LayoutParams).flags.value;

      console.debug("addView: " + viewClass + ", flags=0x" + paramFlags.toString(16));

      if ((paramFlags & FLAG_SECURE) !== 0) {
        console.debug("FLAG_SECURE detected in addView found - removing");
        Java.cast(params, LayoutParams).flags.value = paramFlags & ~FLAG_SECURE;
      }
    } catch (err) {
      console.error("Error patching flags in addView: " + err);
    }

    return addView.call(this, view, params);
  };
});
