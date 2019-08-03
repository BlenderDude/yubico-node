"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __asyncValues = (this && this.__asyncValues) || function (o) {
    if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
    var m = o[Symbol.asyncIterator], i;
    return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function () { return this; }, i);
    function verb(n) { i[n] = o[n] && function (v) { return new Promise(function (resolve, reject) { v = o[n](v), settle(resolve, reject, v.done, v.value); }); }; }
    function settle(resolve, reject, d, v) { Promise.resolve(v).then(function(v) { resolve({ value: v, done: d }); }, reject); }
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var https = require("https");
var Response_1 = require("./Response");
// Default API servers provided from Yubico
var API_SERVERS = ["api.yubico.com", "api2.yubico.com", "api3.yubico.com", "api4.yubico.com", "api5.yubico.com"];
/**
 * The class that manages the Yubico requests and stores data about the
 * client such as its ID and secret
 */
var Yubico = /** @class */ (function () {
    function Yubico(options) {
        // Pull options from the constructor or from environment variables
        if (options && options.clientId) {
            this.clientId = options.clientId;
        }
        else {
            if (!process.env.YUBICO_CLIENT_ID) {
                throw new Error("Either clientId must be set in the constructor, or YUBICO_CLIENT_ID set as an environment variable");
            }
            this.clientId = process.env.YUBICO_CLIENT_ID;
        }
        if (options && options.secret) {
            this.secret = options.secret;
        }
        else {
            if (!process.env.YUBICO_SECRET) {
                throw new Error("Either clientId must be set in the constructor, or YUBICO_SECRET set as an environment variable");
            }
            this.secret = process.env.YUBICO_SECRET;
        }
        if (options && options.sl) {
            this.sl = options.sl;
        }
        else {
            this.sl = process.env.YUBICO_SL;
        }
        if (options && options.timeout) {
            this.timeout = options.timeout;
        }
        else {
            this.timeout = process.env.YUBICO_TIMEOUT ? parseInt(process.env.YUBICO_TIMEOUT, 10) : undefined;
        }
        if (options && options.apiServers) {
            this.apiServers = options.apiServers;
        }
        else {
            this.apiServers = process.env.YUBICO_API_SERVERS ? process.env.YUBICO_API_SERVERS.split(",") : API_SERVERS;
        }
    }
    /**
     * Verify a key against the Yubico servers
     * @param otp {string} The OTP provided from the YubiKey to use to verify
     * @returns {Promise<Response>} The response instance that can be picked apart for values like the serial number
     */
    Yubico.prototype.verify = function (otp) {
        return __awaiter(this, void 0, void 0, function () {
            var e_1, _a, nonce, requestParams, hash, failedResponses, cancellationCallbacks, requestPromises, requestPromises_1, requestPromises_1_1, res, e_1_1;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        nonce = crypto.randomBytes(16).toString("hex");
                        requestParams = new URLSearchParams();
                        // Append all of the required parameters
                        requestParams.append("id", this.clientId);
                        requestParams.append("otp", otp);
                        requestParams.append("timestamp", "1");
                        requestParams.append("nonce", nonce);
                        if (this.sl) {
                            requestParams.append("sl", this.sl);
                        }
                        if (this.timeout) {
                            requestParams.append("timeout", this.timeout.toString());
                        }
                        // Sort them to properly allow for the security hash
                        requestParams.sort();
                        hash = crypto
                            .createHmac("sha1", Buffer.from(this.secret, "base64"))
                            .update(requestParams.toString())
                            .digest("base64");
                        requestParams.append("h", hash);
                        failedResponses = [];
                        cancellationCallbacks = [];
                        requestPromises = this.apiServers.map(function (apiServer) {
                            return new Promise(function (resolve) {
                                // Create a URL object for the request
                                var url = new URL("https://" + apiServer + "/wsapi/2.0/verify");
                                // Set the search of the url to the request param string
                                url.search = requestParams.toString();
                                var req = https.get(url.href, function (res) {
                                    // The data we get will be text, so parse as utf8
                                    res.setEncoding("utf8");
                                    // Collect the chunks of data as they come in
                                    var incomingData = "";
                                    res.on("data", function (chunk) {
                                        incomingData += chunk;
                                    });
                                    // When the request is completed, check for the 200 status code and
                                    // resolve with the data
                                    res.on("end", function () {
                                        if (res.statusCode !== 200) {
                                            resolve(undefined);
                                        }
                                        else {
                                            resolve(Response_1.Response.fromRawBody(incomingData));
                                        }
                                    });
                                    res.on("error", function () { return resolve(undefined); });
                                });
                                // Add a callback to allow the request to be cancelled
                                cancellationCallbacks.push(function () {
                                    // Upon cancellation, abort the HTTP request and resolve
                                    req.abort();
                                    resolve(undefined);
                                });
                                // If the request errors, reject with the error
                                req.on("error", function () { return resolve(undefined); });
                                // Close the write stream to send the request
                                req.end();
                            });
                        });
                        _b.label = 1;
                    case 1:
                        _b.trys.push([1, 6, 7, 12]);
                        requestPromises_1 = __asyncValues(requestPromises);
                        _b.label = 2;
                    case 2: return [4 /*yield*/, requestPromises_1.next()];
                    case 3:
                        if (!(requestPromises_1_1 = _b.sent(), !requestPromises_1_1.done)) return [3 /*break*/, 5];
                        res = requestPromises_1_1.value;
                        // If there was no response, either the request was cancelled or the
                        // network failed, so we can continue to the next one
                        if (!res) {
                            return [3 /*break*/, 4];
                        }
                        // Check the status to determine if we need to return it
                        if (res.getStatus() === Response_1.ResponseStatus.OK) {
                            // Validate the response (this will throw if it fails)
                            // If any one server fails to validate, everything should
                            // fail because this means there is a possible man in the
                            // middle attack.
                            res.validate(nonce, this.secret, otp);
                            // Cancel all of the remaining requests
                            cancellationCallbacks.map(function (cb) { return cb(); });
                            return [2 /*return*/, res];
                        }
                        else {
                            // If the response status is not OK, push it on the failed responses array
                            failedResponses.push(res);
                        }
                        _b.label = 4;
                    case 4: return [3 /*break*/, 2];
                    case 5: return [3 /*break*/, 12];
                    case 6:
                        e_1_1 = _b.sent();
                        e_1 = { error: e_1_1 };
                        return [3 /*break*/, 12];
                    case 7:
                        _b.trys.push([7, , 10, 11]);
                        if (!(requestPromises_1_1 && !requestPromises_1_1.done && (_a = requestPromises_1.return))) return [3 /*break*/, 9];
                        return [4 /*yield*/, _a.call(requestPromises_1)];
                    case 8:
                        _b.sent();
                        _b.label = 9;
                    case 9: return [3 /*break*/, 11];
                    case 10:
                        if (e_1) throw e_1.error;
                        return [7 /*endfinally*/];
                    case 11: return [7 /*endfinally*/];
                    case 12:
                        // If there were no failed responses (or successes as they would return)
                        // throw a network error.
                        if (failedResponses.length === 0) {
                            throw new Error("Yubico API server network error");
                        }
                        // Validate one of the failed responses to throw the appropriate error
                        failedResponses[0].validate(nonce, this.secret, otp);
                        // Return the response if no error throws (this code should be unreachable)
                        return [2 /*return*/, failedResponses[0]];
                }
            });
        });
    };
    return Yubico;
}());
exports.Yubico = Yubico;
