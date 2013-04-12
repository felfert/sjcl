/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Michael Brooks
 */

/** @constructor
 * @class Random number generator
 *
 * @description
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 */
sjcl.prng = function(paranoia) {

  /* private */
  this._pools                   = [new sjcl.hash.sha256()];
  this._poolEntropy             = [0];
  this._reseedCount             = 0;
  this._robins                  = {};
  this._eventId                 = 0;

  this._collectorIds            = {};
  this._collectorIdNext         = 0;

  this._strength                = 0;
  this._poolStrength            = 0;
  this._nextReseed              = 0;
  this._key                     = [0,0,0,0,0,0,0,0];
  this._counter                 = [0,0,0,0];
  this._cipher                  = undefined;
  this._defaultParanoia         = paranoia || 6;

  /* event listener stuff */
  this._collectorsStarted       = false;
  this._callbacks               = {progress: {}, seeded: {}};
  this._callbackI               = 0;
  /* html5 worker environment */
  this._isWorker                = (typeof self.WorkerLocation !== 'undefined');

  /* constants */
  this._NOT_READY               = 0;
  this._READY                   = 1;
  this._REQUIRES_RESEED         = 2;

  this._MAX_WORDS_PER_BURST     = 65536;
  this._PARANOIA_LEVELS         = [0,48,64,96,128,192,256,384,512,768,1024];
  this._MILLISECONDS_PER_RESEED = 30000;
  this._BITS_PER_RESEED         = 80;

  if (this._isWorker) {
    // In a worker we must wait until the GUI thread is prep'd and sends
    // us the persistent pool data
    self.addEventListener('message', this.initHandler.bind(this));
    // Tell the GUI thread, that we are ready to receive
    self.postPessage({'state':'prnginit'});
  } else {
    this.init();
  }
};

sjcl.prng.prototype = {

  initHandler: function(evt) {
    if (evt.data && evt.data.hasOwnProperty('init') && evt.data.hasOwnProperty('pool')) {
      this.init(evt.data.pool);
    }
  },

  /** Prepare the entorpy pools for use.
  */
  init: function(poolData) {
    var r, x, handler;
    /* sjcl.prng is useless without the following line,  
     * this should be started as soon as possilbe to collect the most
     * entorpy*/
    this.startCollectors();

    /*Initlize the entropy pool with information the attacker doesn't 
     *know*/
    for(x=0; x<48; x++){
      r = this._platformPRNG();
      this.addEntropy(r, 1, "init");
    }

    /*If sjcl.prng has run before then we should have a previous 
     * state to draw from*/
    if (this._isWorker) {
      handler = function(evt) {
        var data = evt.data;
        if (data.type === undefined) {
          return; // Not for us
        }
        if (data.type === 'event' && data.what === 'beforeunload') {
          this._savePoolState();
        }
      };
      this.addEntropy(self.location.href, 0, "location");
      this._loadPoolState(poolData);
      self.addEventListener('message', handler.bind(this));
      self.postMessage({'state':'listen', 'events':'beforeunload'});
    } else {
      /*We should be over https and these would be valid secrets.
       * Worst case adding more data doesn't hurt*/
      this.addEntropy(document.cookie, 0, "cookie");
      this.addEntropy(document.location.href, 0, "location");

      this._loadPoolState();
      if (window.addEventListener) {
        window.addEventListener("beforeunload", this._savePoolState.bind(this), false);
      } else if (document.attachEvent) {
        document.attachEvent("onbeforeunload", this._savePoolState.bind(this));
      }
    }
  },

  /** Generate several random words, and return them in an array
   * @param {Number} nwords The number of words to generate.
   */
  randomWords: function (nwords, paranoia) {
    var out = [], i, readiness = this.isReady(paranoia), g;

    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }

    for (i=0; i<nwords; i+= 4) {
      if ((i+1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }

      g = this._gen4words();
      out.push(g[0],g[1],g[2],g[3]);
    }
    this._gate();

    return out.slice(0,nwords);
  },

  setDefaultParanoia: function (paranoia) {
    this._defaultParanoia = paranoia;
  },

  /**
   * Add entropy to the pools.
   * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
   * @param {Number} estimatedEntropy The estimated entropy of data, in bits
   * @param {String} source The source of the entropy, eg "mouse"
   */
  addEntropy: function (data, estimatedEntropy, source) {
    source = source || "user";

    var id,
        i, tmp, objName,
        t = (new Date()).valueOf(),
        r = this._platformPRNG(),
        robin = this._robins[source],
        oldReady = this.isReady(), err = 0;

    id = this._collectorIds[source];
    if (id === undefined) { id = this._collectorIds[source] = this._collectorIdNext ++; }

    if (robin === undefined) { robin = this._robins[source] = 0; }
    this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;

    switch(typeof(data)) {

      case "number":
        if (estimatedEntropy === undefined) {
          estimatedEntropy = 1;
        }
        this._pools[robin].update([id,this._eventId++,1,estimatedEntropy,t,r,1,data|0]);
        break;

      case "object":
        objName = Object.prototype.toString.call(data);
        if (objName === "[object Uint32Array]") {
          tmp = [];
          for (i = 0; i < data.length; i++) {
            tmp.push(data[i]);
          }
          data = tmp;
        } else {
          if (objName !== "[object Array]") {
            err = 1;
          }
          for (i=0; i<data.length && !err; i++) {
            if (typeof(data[i]) !== "number") {
              err = 1;
            }
          }
        }
        if (!err) {
          if (estimatedEntropy === undefined) {
            /* horrible entropy estimator */
            estimatedEntropy = 0;
            for (i=0; i<data.length; i++) {
              tmp= data[i];
              while (tmp>0) {
                estimatedEntropy++;
                tmp = tmp >>> 1;
              }
            }
          }
          this._pools[robin].update([id,this._eventId++,2,estimatedEntropy,t,r,data.length].concat(data));
        }
        break;

      case "string":
        if (estimatedEntropy === undefined) {
          /* English text has just over 1 bit per character of entropy.
           * But this might be HTML or something, and have far less
           * entropy than English...  Oh well, let's just say one bit.
           */
          estimatedEntropy = data.length;
        }
        this._pools[robin].update([id,this._eventId++,3,estimatedEntropy,t,r,data.length]);
        this._pools[robin].update(data);
        break;

      default:
        err=1;
    }
    if (err) {
      throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
    }

    /* record the new strength */
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;

    /* fire off events */
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },

  /** Is the generator ready? */
  isReady: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ (paranoia !== undefined) ? paranoia : this._defaultParanoia ];

    if (this._strength && this._strength >= entropyRequired) {
      return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
        this._REQUIRES_RESEED | this._READY :
        this._READY;
    } else {
      return (this._poolStrength >= entropyRequired) ?
        this._REQUIRES_RESEED | this._NOT_READY :
        this._NOT_READY;
    }
  },

  /** Get the generator's progress toward readiness, as a fraction */
  getProgress: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._defaultParanoia ];

    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return (this._poolStrength > entropyRequired) ?
        1.0 :
        this._poolStrength / entropyRequired;
    }
  },

  /** start the built-in entropy collectors */
  startCollectors: function () {
    if (this._collectorsStarted) { return; }

    if (this.isWorker) {
      // Executed inside a html5 web worker: communicate with the
      // main GUI thread via messages.
      var handler = function(evt) {
        var data = evt.data;
        if (data.type === undefined) {
          return; // Not for us
        }
        if (data.type === 'event') {
          switch (data.what) {
            case 'mousemove':
              this._mouseCollector({
                'x':data.x,
                'y':data.y
              });
              break;
            case 'keypress':
              this._keyboardCollector({
                'charCode':data.cc,
                'keyCode':data.kc
              });
              break;
            case 'devicemotion':
              this._accelerometerCollector({
                'accelerationIncludingGravity':{
                  'x': data.x,
                  'y': data.y,
                  'z': data.z
                }
              });
              break;
          }
        }
      };
      this._collHandler = handler.bind(this);
      self.addEventListener('message', this._collHandler);
      // Tell the main GUI thread the events it should forward to us via messages
      self.postMessage({'state':'listen', 'events':['mousemove','keypress','devicemotion']});
    } else {
      // Executed in a "regular" browser engine.

      /* Since bind creates a *new* function, we must save that in order to
       * be able to unbind it.
       */
      this._mouseCollectorBound = this._mouseCollector.bind(this);
      this._keyboardCollectorBound = this._keyboardCollector.bind(this);
      this._accelerometerCollectorBound = this._accelerometerCollector.bind(this);
      if (window.addEventListener) {
        window.addEventListener("mousemove", this._mouseCollectorBound, false);
        window.addEventListener("keypress", this._keyboardCollectorBound, false);
        window.addEventListener("devicemotion", this._accelerometerCollectorBound, false);
      } else if (document.attachEvent) {
        document.attachEvent("onmousemove", this._mouseCollectorBound);
        document.attachEvent("onkeypress", this._keyboardCollectorBound);
        document.attachEvent("ondevicemotion", this._accelerometerCollectorBound);
      } else {
        throw new sjcl.exception.bug("can't attach event");
      }
    }
    this._collectorsStarted = true;
  },

  /** stop the built-in entropy collectors */
  stopCollectors: function () {
    if (!this._collectorsStarted) { return; }

    if (this.isWorker) {
      self.removeEventListener('message', this._collHandler);
      self.postMessage({'state':'unlisten', 'events':['mousemove','keypress','devicemotion']});
    } else {
      if (window.removeEventListener) {
        window.removeEventListener("mousemove", this._mouseCollectorBound, false);
        window.removeEventListener("keypress", this._keyboardCollectorBound, false);
        window.removeEventListener("devicemotion", this._accelerometerCollectorBound, false);      
      } else if (window.detachEvent) {
        window.detachEvent("onmousemove", this._mouseCollectorBound);
        window.detachEvent("onkeypress", this._keyboardCollectorBound);
        window.detachEvent("ondevicemotion", this._accelerometerCollectorBound);      
      }
    }
    this._collectorsStarted = false;
  },

  /** add an event listener for progress or seeded-ness. */
  addEventListener: function (name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },

  /** remove an event listener for progress or seeded-ness */
  removeEventListener: function (name, cb) {
    var i, j, cbs=this._callbacks[name], jsTemp=[];

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
      if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }

    for (i=0; i<jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },

  /** Generate 4 random words, no reseed, no gate.
   * @private
   */
  _gen4words: function () {
    var i;
    for (i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
    return this._cipher.encrypt(this._counter);
  },

  /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
   * @private
   */
  _gate: function () {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },

  /** Reseed the generator with the given words
   * @private
   */
  _reseed: function (seedWords) {
    var i;
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
  },

  /** reseed the data from the entropy pools
   * @param full If set, use all the entropy pools in the reseed.
   */
  _reseedFromPools: function (full) {
    var reseedData = [], strength = 0, i;

    this._nextReseed = reseedData[0] =
      (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;

    for (i=0; i<16; i++) {
      /* On some browsers, this is cryptographically random.  So we might
       * as well toss it in the pot and stir...
       */
      reseedData.push(this._platformPRNG());
    }

    for (i=0; i<this._pools.length; i++) {
      reseedData = reseedData.concat(this._pools[i].finalize());
      strength += this._poolEntropy[i];
      this._poolEntropy[i] = 0;

      if (!full && (this._reseedCount & (1<<i))) { break; }
    }

    /* if we used the last pool, push a new one onto the stack */
    if (this._reseedCount >= 1 << this._pools.length) {
      this._pools.push(new sjcl.hash.sha256());
      this._poolEntropy.push(0);
    }

    /* how strong was this reseed? */
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }

    this._reseedCount ++;
    this._reseed(reseedData);
  },

  _keyboardCollector: function (ev) {
    var chCode = ('charCode' in ev) ? ev.charCode : ev.keyCode;
    this.addEntropy(chCode, 1, "keyboard");
  },

  _mouseCollector: function (ev) {
    var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
    this.addEntropy([x,y], 2, "mouse");
  },

  _accelerometerCollector: function (ev) {
    this.addEntropy([
        ev.accelerationIncludingGravity.x||'',
        ev.accelerationIncludingGravity.y||'',
        ev.accelerationIncludingGravity.z||'',
        (window && window.orientation)||''
        ], 3, "accelerometer");
  },

  _fireEvent: function (name, arg) {
    var j, cbs = this._callbacks[name], cbsTemp=[];
    /* TODO: there is a race condition between removing collectors and firing them */ 

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
      if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
      }
    }

    for (j=0; j<cbsTemp.length; j++) {
      cbsTemp[j](arg);
    }
  },

  _savePoolState: function () {
    var saveData = this.randomWords(4);
    if (this.isWorker) {
      self.postMessage({'state':'savepool','data':saveData});
    } else if (window.localStorage){
      window.localStorage.setItem("sjcl.prng", saveData);
    }
  },

  _loadPoolState: function (poolData) {
    if((!this._isWorker) && window.localStorage){
      poolData = window.localStorage.getItem("sjcl.prng");
    }
    if(poolData){
      /* Assume the worst, that localStorage was compromised with
       * XSS and therefore contributes a worst case of 0 entropy*/
      this.addEntropy(poolData, 0, "loadpool");
    }
  },

  /** Return the best random value aviable to this script.
  */
  _platformPRNG: function () {
    var ret, ab;
    // Unfortunately, in a worker there's currently no access to builtin
    // crypto. In fact, it would be much easier to access /dev/random from
    // a worker. It's discussed at W3C but until then ...
    // See: http://lists.w3.org/Archives/Public/public-webcrypto/2012Oct/0076.html
    //
    if ((!this._isWorker) && typeof window.crypto.getRandomValues === 'function'){
      ab = new Uint32Array(1);
      window.crypto.getRandomValues(ab);
      ret = ab[0];
    }else{
      /*This is the best we can do,  
       *this method is cryptographically random on some platforms*/
      ret = Math.random()*0x100000000|0;
    }
    return ret;
  }
};

sjcl.random = new sjcl.prng(6);
