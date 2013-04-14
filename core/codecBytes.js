/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Arrays of bytes */
sjcl.codec.bytes = function() {
    var me = this;
    me._listeners = [];
};

sjcl.codec.bytes.prototype = {

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

    /** Convert from a bitArray to an array of bytes. */
    fromBits: function (arr) {
        var out = [], bl = sjcl.bitArray.bitLength(arr), i, tmp;
        for (i=0; i<bl/8; ++i) {
            if ((i&3) === 0) {
                tmp = arr[i/4];
            }
            out.push(tmp >>> 24);
            tmp <<= 8;
            if (0 === (i & 0x0FFFFF)) {
                // fire a progress event every MiB
                this._fireProgress(['finish', i, bl/8]);
            }
        }
        return out;
    },

    /** Convert from a bitArray to an ArrayBuffer. */
    toArrayBuffer: function (arr) {
        var bl = sjcl.bitArray.bitLength(arr) / 8, l, out, dv, i, tmp;
        out = new ArrayBuffer(bl);
        dv = new DataView(out);
        l = bl & ~3;
        for (i=0; i<l; i+=4) {
            dv.setInt32(i, arr[i/4]);
            if (0 === (i & 0x0FFFFF)) {
                // fire a progress event every MiB
                this._fireProgress(['finish', i, bl]);
            }
        }
        for (i=l; i<bl; ++i) {
            if ((i&3) === 0) {
                tmp = arr[i/4];
            }
            dv.setUint8(i, tmp >>> 24);
            tmp <<= 8;
        }
        return out;
    },

    /** Convert from an ArrayBuffer to a bitArray. */
    fromArrayBuffer: function (bytes) {
        var out = [], i, l = bytes.byteLength & ~3, tmp=0;
        var dv = new DataView(bytes);
        for (i=0; i<l; i+=4) {
            out.push(dv.getInt32(i));
            if (0 === (i & 0x0FFFFF)) {
                // fire a progress event every MiB
                this._fireProgress(['prepare', i, bytes.byteLength]);
            }
        }
        if (l < bytes.byteLength) {
            for (i=l; i<bytes.byteLength; ++i) {
                tmp = tmp << 8 | dv.getUint8(i);
            }
            out.push(sjcl.bitArray.partial(8*(i&3), tmp));
        }
        return out;
    },

    /** Convert from an array of bytes to a bitArray. */
    toBits: function (bytes) {
        var out = [], i, tmp=0;
        for (i=0; i<bytes.length; ++i) {
            tmp = tmp << 8 | bytes[i];
            if ((i&3) === 3) {
                out.push(tmp);
                tmp = 0;
            }
            if (0 === (i & 0x0FFFFF)) {
                // fire a progress event every MiB
                this._fireProgress(['prepare', i, bytes.length]);
            }
        }
        if (i&3) {
            out.push(sjcl.bitArray.partial(8*(i&3), tmp));
        }
        return out;
    }
};

/* vi:set expandtab shiftwidth=2 tabstop=2: */
