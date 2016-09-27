function createKeyFromHexSeed(seed) { 
   return CoinStack.Util.bitcoin().HDNode.fromSeedHex(seed, CoinStack.Util.bitcoin().networks.bitcoin).privKey.toWIF()
}

function FingerprintKey() {
}

FingerprintKey.prototype.initKey = function (params, successCallback, errorCallback) {
    cordova.exec(
        function(res) {
            if (res.status == "ok") {
                res.key = createKeyFromHexSeed(res.key);
            }
            successCallback(res);
        },
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
        function(res) {
            if (res.status == "ok") {
                res.key = createKeyFromHexSeed(res.key);
            }
            successCallback(res);
        },
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