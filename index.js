'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.CurveP256 = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); // Simple ECDSA supports creation of keypair,
// signing and verification. Public Key, Private Key and Signatures
// are ASN.1/DER encoded.


var _elliptic = require('elliptic');

var _elliptic2 = _interopRequireDefault(_elliptic);

var _util = require('util');

var _util2 = _interopRequireDefault(_util);

var _asn = require('asn1.js');

var _asn2 = _interopRequireDefault(_asn);

var _bn = require('bn.js');

var _bn2 = _interopRequireDefault(_bn);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var EC = _elliptic2.default.ec;

var CurveP256 = exports.CurveP256 = "p256";

var PubKeyAsn1 = _asn2.default.define('PubKey', function () {
    this.seq().obj(this.key("x").utf8str(), this.key("y").utf8str());
});

var PrivKeyAsn1 = _asn2.default.define('PrivKey', function () {
    this.seq().obj(this.key("d").utf8str());
});

var SigAsn1 = _asn2.default.define("Sig", function () {
    this.seq().obj(this.key("r").utf8str(), this.key("s").utf8str());
});

var SimpleECDSA = function () {

    /**
     * Initialize the class. Throws error if curveName is
     * unsupported.
     * 
     * @param curveName {String} The curve name
     */
    function SimpleECDSA(curveName) {
        _classCallCheck(this, SimpleECDSA);

        this.curve = null;
        this.privKey = null;
        this.ec = null;
        this.key = null;

        switch (curveName) {
            case CurveP256:
                this.curve = CurveP256;
                this.ec = new EC(CurveP256);
                break;
            default:
                throw new Error("unsupported elliptic curve");
        }

        this.genKey();
    }

    /**
     * Generate a keypair
     */


    _createClass(SimpleECDSA, [{
        key: 'genKey',
        value: function genKey() {
            this.key = this.ec.genKeyPair();
        }

        /**
         * Get ASN.1/DER encoded public key.
         * 
         * @return {String} ASN.1/DER encoded public key outputed as hex. 
         */

    }, {
        key: 'getPubKey',
        value: function getPubKey() {
            var pub = this.key.getPublic();
            var output = PubKeyAsn1.encode({
                x: pub.getX().toString(10),
                y: pub.getY().toString(10)
            }, "der");
            return output.toString('hex');
        }

        /**
         * Get ASN.1/DER encoded private key
         * @return ASN.1/DER encoded private key outputed as hex. 
         */

    }, {
        key: 'getPrivKey',
        value: function getPrivKey() {
            var output = PrivKeyAsn1.encode({
                d: this.key.priv.toString(10)
            }, "der");
            return output.toString('hex');
        }

        /**
         * Sign a message.
         * 
         * @param msg {String} The message to sign
         * @return {String} The ASN.1/DER, hex encoded signature
         */

    }, {
        key: 'sign',
        value: function sign(msg) {
            var sig = this.key.sign(msg);
            var output = SigAsn1.encode({
                r: sig.r.toString(10),
                s: sig.s.toString(10)
            }, "der");
            return output.toString("hex");
        }

        /**
         * Verify a signature.
         * 
         * @param pubKey {String} The public key
         * @param curveName {String} The elliptic curve of the public key
         * @param msg {String} The message that was signed
         * @param sig {String} The signature to be verified
         * @return {Boolean} true if successfully verified. Otherwise false.
         */

    }], [{
        key: 'verify',
        value: function verify(pubKey, curveName, msg, sig) {
            var sigFromDer = SigAsn1.decode(new Buffer(sig, "hex"), "der");
            var key = SimpleECDSA.loadFromPubKey(pubKey, curveName).key;
            return key.verify(msg, {
                r: new _bn2.default(sigFromDer.r, 10).toJSON(),
                s: new _bn2.default(sigFromDer.s, 10).toJSON()
            });
        }

        /**
         * Create a SimpleECDSA object from an ASN.1/DER private key
         * 
         * @param privKey {String} The ASN.1/DER encoded private key
         * @param curveName {String} The curve name
         * @return {SimpleECDSA}
         */

    }, {
        key: 'loadFromPrivKey',
        value: function loadFromPrivKey(privKey, curveName) {
            var privKeyFromDer = PrivKeyAsn1.decode(new Buffer(privKey, "hex"), "der");
            var key = new EC(CurveP256).keyFromPrivate(new _bn2.default(privKeyFromDer.d, 10).toJSON(), "hex");
            var se = new SimpleECDSA(curveName);
            se.key = key;
            return se;
        }

        /**
         * Create a SimpleECDSA object from an ASN.1/DER public key
         * 
         * @param pubKey {String} The ASN.1/DER encoded public key
         * @param curveName {String} The curve name
         * @return {SimpleECDSA}
         */

    }, {
        key: 'loadFromPubKey',
        value: function loadFromPubKey(pubKey, curveName) {
            var pubKeyFromDer = PubKeyAsn1.decode(new Buffer(pubKey, "hex"), "der");
            var key = new EC(CurveP256).keyFromPublic({
                x: new _bn2.default(pubKeyFromDer.x, 10).toJSON(),
                y: new _bn2.default(pubKeyFromDer.y, 10).toJSON()
            }, "hex");
            var se = new SimpleECDSA(curveName);
            se.key = key;
            return se;
        }

        /**
         * Checks if a public key is valid. A valid key
         * must be ASN.1/DER decodable. No exception is thrown.
         * 
         * @param pubKey {String} The public key
         * @return {Boolean} true if valid, otherwise false.
         */

    }, {
        key: 'isValidPubKey',
        value: function isValidPubKey(pubKey) {
            try {
                var se = SimpleECDSA.loadFromPubKey(pubKey);
                return true;
            } catch (e) {
                return false;
            }
        }
    }]);

    return SimpleECDSA;
}();

exports.default = SimpleECDSA;
