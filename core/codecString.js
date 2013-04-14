/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
/** @namespace UTF-8 strings */
sjcl.codec.utf8String = function() {
    var me = this;
    me._listeners = [];
};

sjcl.codec.utf8String.prototype = {

    /* private */
    _fireProgress: function(args) {
        var j;
        for (j = 0; j < this._listeners.length; ++j) {
            this._listeners[j].fn.apply(this._listeners[j].scope, args);
        }
    },
    /** add an event listener */
    addEventListener: function (name, callback, scope) {
        if (name === 'progress') {
            scope = scope || this;
            this._listeners.push({fn:callback,scope:scope});
        }
    },
    /** remove an event listener */
    removeEventListener: function (name, callback, scope) {
        var j;
        if (name === 'progress') {
            scope = scope || this;
            for (j = 0; j < this._listeners.length; ++j) {
                if ((this._listeners[j].fn === callback) && (this._listeners[j].scope === scope)) {
                    this._listeners.splice(j, 1);
                }
            }
        }
    },

    /** Convert from a bitArray to a UTF-8 string. */
    fromBits: function (arr) {
        var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
        for (i=0; i<bl/8; i++) {
            if ((i&3) === 0) {
                tmp = arr[i/4];
            }
            out += String.fromCharCode(tmp >>> 24);
            tmp <<= 8;
            if (0 === (i & 0x0FFFFF)) {
                // fire a progress event every MiB
                this._fireProgress(['finish', i, bl/8]);
            }
        }
        return decodeURIComponent(escape(out));
    },

    /** Convert from a UTF-8 string to a bitArray. */
    toBits: function (str) {
        str = unescape(encodeURIComponent(str));
        var out = [], i, tmp=0;
        for (i=0; i<str.length; i++) {
            tmp = tmp << 8 | str.charCodeAt(i);
            if ((i&3) === 3) {
                out.push(tmp);
                tmp = 0;
            }
            if (0 === (i & 0x0FFFFF)) {
                // fire a progress event every MiB
                this._fireProgress(['prepare', i, str.length]);
            }
        }
        if (i&3) {
            out.push(sjcl.bitArray.partial(8*(i&3), tmp));
        }
        return out;
    }
};

/* vi:set expandtab shiftwidth=2 tabstop=2: */
