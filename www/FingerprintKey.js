function FingerprintKey() {
}

FingerprintKey.prototype.initKey = function (params, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintKey",  // Java Class
        "initkey", // action
        [ // Array of arguments to pass to the Java class
            params
        ]
    );
};

FingerprintKey.prototype.fetchKey = function (params, successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintKey",  // Java Class
        "fetchkey", // action
        [ // Array of arguments to pass to the Java class
            params
        ]
    );
};

FingerprintKey.prototype.isAvailable = function (successCallback, errorCallback) {
    cordova.exec(
        successCallback,
        errorCallback,
        "FingerprintKey",  // Java Class
        "availability", // action
        [{}]
    );
};

FingerprintKey = new FingerprintKey();
module.exports = FingerprintKey;

// FingerprintKey.initKey({keyId: "testKey", locale: {desc:"desc", cancel:"cancel", title:"title", hint:"hint", success:"success", notrecognized:"notrecognized"}}, function(res){console.log(res);}, function(res){console.log(res)});