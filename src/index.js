// Simple ECDSA supports creation of keypair,
// signing and verification. Public Key, Private Key and Signatures
// are ASN.1/DER encoded.
import elliptic from 'elliptic';
import util from 'util'
import asn1js from 'asn1.js'
import BN from 'bn.js'

let EC = elliptic.ec

export const CurveP256 = "p256"

let PubKeyAsn1 = asn1js.define('PubKey', function(){
    this.seq().obj(
        this.key("x").utf8str(),
        this.key("y").utf8str()
    )
})

let PrivKeyAsn1 = asn1js.define('PrivKey', function(){
    this.seq().obj(
        this.key("d").utf8str()
    )
})

let SigAsn1 = asn1js.define("Sig", function(){
    this.seq().obj(
        this.key("r").utf8str(),
        this.key("s").utf8str()
    )
})

export default class SimpleECDSA {

    /**
     * Initialize the class. Throws error if curveName is
     * unsupported.
     * 
     * @param curveName {String} The curve name
     */
    constructor(curveName) {
        this.curve = null
        this.privKey = null
        this.ec = null;
        this.key = null;
        
        switch (curveName) {
            case CurveP256:
                this.curve = CurveP256
                this.ec = new EC(CurveP256)
                break
            default:
                throw new Error("unsupported elliptic curve")
        }
        
        this.genKey()
    }
    
    /**
     * Generate a keypair
     */
    genKey() {
        this.key = this.ec.genKeyPair()
    }
    
    /**
     * Get ASN.1/DER encoded public key.
     * 
     * @return {String} ASN.1/DER encoded public key outputed as hex. 
     */
    getPubKey() {
        let pub = this.key.getPublic()
        var output = PubKeyAsn1.encode({
            x: pub.getX().toString(10),
            y: pub.getY().toString(10)
        }, "der")
        return output.toString('hex')
    }
    
    /**
     * Get ASN.1/DER encoded private key
     * @return ASN.1/DER encoded private key outputed as hex. 
     */
    getPrivKey() {
        var output = PrivKeyAsn1.encode({
            d: this.key.priv.toString(10),
        }, "der")
        return output.toString('hex')
    }
    
    /**
     * Sign a message.
     * 
     * @param msg {String} The message to sign
     * @return {String} The ASN.1/DER, hex encoded signature
     */
    sign(msg) {
        let sig = this.key.sign(msg)
        var output = SigAsn1.encode({
            r: sig.r.toString(10),
            s: sig.s.toString(10),
        }, "der")
        return output.toString("hex")
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
    static verify(pubKey, curveName, msg, sig) {
        let sigFromDer = SigAsn1.decode(new Buffer(sig, "hex"), "der")
        let key = SimpleECDSA.loadFromPubKey(pubKey, curveName).key
        return key.verify(msg, {
            r: new BN(sigFromDer.r, 10).toJSON(),
            s: new BN(sigFromDer.s, 10).toJSON()
        })        
    }
    
    /**
     * Create a SimpleECDSA object from an ASN.1/DER private key
     * 
     * @param privKey {String} The ASN.1/DER encoded private key
     * @param curveName {String} The curve name
     * @return {SimpleECDSA}
     */
    static loadFromPrivKey(privKey, curveName) {
        let privKeyFromDer = PrivKeyAsn1.decode(new Buffer(privKey, "hex"), "der")
        let key = new EC(CurveP256).keyFromPrivate(new BN(privKeyFromDer.d, 10).toJSON(), "hex")
        let se = new SimpleECDSA(curveName)
        se.key = key
        return se
    }
    
    /**
     * Create a SimpleECDSA object from an ASN.1/DER public key
     * 
     * @param pubKey {String} The ASN.1/DER encoded public key
     * @param curveName {String} The curve name
     * @return {SimpleECDSA}
     */
    static loadFromPubKey(pubKey, curveName) {
        let pubKeyFromDer = PubKeyAsn1.decode(new Buffer(pubKey, "hex"), "der")
        let key = new EC(CurveP256).keyFromPublic({
            x: new BN(pubKeyFromDer.x, 10).toJSON(), 
            y: new BN(pubKeyFromDer.y, 10).toJSON()
        }, "hex")
        let se = new SimpleECDSA(curveName)
        se.key = key
        return se
    }
    
    /**
     * Checks if a public key is valid. A valid key
     * must be ASN.1/DER decodable. No exception is thrown.
     * 
     * @param pubKey {String} The public key
     * @return {Boolean} true if valid, otherwise false.
     */
    static isValidPubKey(pubKey) {
        try {
            let se = SimpleECDSA.loadFromPubKey(pubKey)
            return true
        } catch(e) {
            return false
        }
    }
}
