"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var ResponseStatus;
(function (ResponseStatus) {
    ResponseStatus["OK"] = "OK";
    ResponseStatus["BAD_OTP"] = "BAD_OTP";
    ResponseStatus["REPLAYED_OTP"] = "REPLAYED_OTP";
    ResponseStatus["BAD_SIGNATURE"] = "BAD_SIGNATURE";
    ResponseStatus["MISSING_PARAMETER"] = "MISSING_PARAMETER";
    ResponseStatus["NO_SUCH_CLIENT"] = "NO_SUCH_CLIENT";
    ResponseStatus["OPERATION_NOT_ALLOWED"] = "OPERATION_NOT_ALLOWED";
    ResponseStatus["BACKEND_ERROR"] = "BACKEND_ERROR";
    ResponseStatus["NOT_ENOUGH_ANSWERS"] = "NOT_ENOUGH_ANSWERS";
    ResponseStatus["REPLAYED_REQUEST"] = "REPLAYED_REQUEST";
})(ResponseStatus = exports.ResponseStatus || (exports.ResponseStatus = {}));
var Response = /** @class */ (function () {
    function Response(otp, nonce, h, t, status, timestamp, sessioncounter, sessionuse, sl) {
        this.otp = otp;
        this.nonce = nonce;
        this.h = h;
        this.t = t;
        this.status = status;
        this.timestamp = timestamp;
        this.sessioncounter = sessioncounter;
        this.sessionuse = sessionuse;
        this.sl = sl;
    }
    /**
     * Creates a response from a string body
     * @param body {string} Body from the Yubico server
     * @returns {Response} Newly generated Response instance from the input
     */
    Response.fromRawBody = function (body) {
        // Grab all the key balue pairs from the response and
        // split them into an array. We relace the \r\n's with \n's to
        // sanitize the response. Slice off the last 2 elements as they
        // are empty.
        var keyValuePairs = body
            .replace(/\r\n/g, "\n")
            .split("\n")
            .slice(0, -2);
        // Reduce the array in to an object that contains the key
        // value pairs from the response
        var values = keyValuePairs.reduce(function (accumulated, current) {
            var _a;
            // Split the key and the value apart by the '='. Limit the value
            // in case the value contains an '=' in the base64 padding
            var _b = current.split(/=(.+)/), key = _b[0], value = _b[1];
            // Add this key value pair to the object
            return Object.assign(accumulated, (_a = {},
                _a[key] = value,
                _a));
        }, {});
        // Return a Response instance from the parsed values
        return new Response(values.otp, values.nonce, values.h, values.t, values.status, values.timestamp, values.sessioncounter, values.sessionuse, values.sl);
    };
    /**
     * Validate the request against the nonce, secret, and otp
     * @param nonce {string} Nonce used during the request
     * @param secret {string} Secret used to verify against
     * @param otp {string} OTP from when the key was pressed
     */
    Response.prototype.validate = function (nonce, secret, otp) {
        var _this = this;
        var _a;
        if (this.status !== ResponseStatus.OK) {
            var errorMessages = (_a = {},
                _a[ResponseStatus.BAD_OTP] = "The OTP is invalid format",
                _a[ResponseStatus.REPLAYED_OTP] = "The OTP has already been seen by the service.",
                _a[ResponseStatus.BAD_SIGNATURE] = "The HMAC signature verification failed.",
                _a[ResponseStatus.MISSING_PARAMETER] = "The request lacks a parameter.",
                _a[ResponseStatus.NO_SUCH_CLIENT] = "The client id does not exist. If you just registered for one, please give it 10 minutes to propagate",
                _a[ResponseStatus.OPERATION_NOT_ALLOWED] = "The client id is not allowed to verify OTPs.",
                _a[ResponseStatus.BACKEND_ERROR] = "Unexpected error in our server. Please contact Yubico if you see this error.",
                _a[ResponseStatus.NOT_ENOUGH_ANSWERS] = "Server could not get requested number of syncs during before timeout.",
                _a[ResponseStatus.REPLAYED_REQUEST] = "Server has seen the OTP/Nonce combination before",
                _a);
            var errorMessage = errorMessages[this.status];
            if (!errorMessage) {
                throw new Error("Unknown status " + this.status);
            }
            throw new Error(errorMessage);
        }
        if (this.nonce !== nonce) {
            throw new Error("Nonces do not equal");
        }
        // Define the keys used in the hash
        var keys = ["nonce", "otp", "sessioncounter", "sessionuse", "sl", "status", "t", "timestamp"];
        // Concatenate all the keys as they would be used in a HTTP request
        var body = keys
            .filter(function (key) { return _this[key] !== undefined; })
            .sort()
            .map(function (key) { return key + "=" + _this[key]; })
            .join("&");
        // Hash them to compare against the server's assertion
        var hash = crypto
            .createHmac("sha1", Buffer.from(secret, "base64"))
            .update(body)
            .digest("base64");
        // If the hashes diverge, the response should not be trusted and we throw an error
        if (hash !== this.h) {
            throw new Error("Hash provided from server and client hash do not match");
        }
        // If the OTPs don't match, throw an error as the response was tampered with
        // The hash should pick this up, but you can never be too sure
        if (this.otp !== otp) {
            throw new Error("OTPs do not match");
        }
    };
    /**
     * @returns {string} the one time password used in the request
     */
    Response.prototype.getOneTimePassword = function () {
        return this.otp;
    };
    /**
     * @returns {Date} Timestamp of the request in UTC
     */
    Response.prototype.getTimestampUTC = function () {
        return new Date(this.t * 1000);
    };
    /**
     * @returns {Date} YubiKey internal timestamp value when key was pressed
     */
    Response.prototype.getTimestamp = function () {
        return new Date(this.timestamp);
    };
    /**
     * @returns {number} YubiKey internal usage counter when key was pressed
     */
    Response.prototype.getSessionCounter = function () {
        return parseInt(this.sessioncounter, 10);
    };
    /**
     * @returns {number} YubiKey internal session usage counter when key was pressed
     */
    Response.prototype.getSessionUse = function () {
        return parseInt(this.sessionuse, 10);
    };
    /**
     * @returns {ResponseStatus} The status of the request. This will only show OK as all others will throw
     */
    Response.prototype.getStatus = function () {
        return this.status;
    };
    /**
     * @returns {string} The public ID is the first 12 bytes of the OTP, this does not change between each request and can be used to identify users
     */
    Response.prototype.getPublicId = function () {
        return this.otp.substr(0, 12);
    };
    /**
     * @returns {number} The serial number of the key described as a 48 bit number
     */
    Response.prototype.getSerialNumber = function () {
        var publicId = this.getPublicId();
        // Convert the modHex to a UIntBE as described here
        // https://developers.yubico.com/yubico-c/Manuals/modhex.1.html
        var modHexConversion = {
            b: "1",
            c: "0",
            d: "2",
            e: "3",
            f: "4",
            g: "5",
            h: "6",
            i: "7",
            j: "8",
            k: "9",
            l: "A",
            m: "B",
            n: "C",
            r: "D",
            t: "E",
            u: "F",
            v: "G",
        };
        // Do the conversion and return the 48 bit integer
        return Buffer.from(publicId
            .split("")
            .map(function (char) { return modHexConversion[char]; })
            .join(""), "hex").readUIntBE(0, 6);
    };
    return Response;
}());
exports.Response = Response;
