import ObjC from 'frida-objc-bridge';

if (!ObjC.available) {
  throw new Error('Objective-C runtime is unavailable');
}

rpc.exports = {
  bundleIdentifier() {
    return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
  },
  appVersion() {
    const dictionary = ObjC.classes.NSBundle.mainBundle().infoDictionary();
    const version = dictionary.objectForKey_('CFBundleShortVersionString');
    return version === null ? null : version.toString();
  }
};

send({ type: 'ready', objc: true, pid: Process.id });
