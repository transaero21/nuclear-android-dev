Java.perform(function () {
  var Activity = Java.use('android.app.Activity');
  var StringClass = Java.use("java.lang.String");

  Activity.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState) {
    console.debug("Activity onCreate called");

    this.onCreate(savedInstanceState);

    var Builder = Java.use("android.app.AlertDialog$Builder");

    var builder = Builder.$new(this);
    builder.setTitle(StringClass.$new("Uh!"));
    builder.setMessage(StringClass.$new("uhhhhhhh"));
    builder.setPositiveButton(StringClass.$new("OK"), null);

    var dialog = builder.create();
    dialog.show();

    return;
  };
});
