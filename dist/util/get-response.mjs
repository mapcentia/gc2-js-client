var __async = (__this, __arguments, generator) => {
  return new Promise((resolve, reject) => {
    var fulfilled = (value) => {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    };
    var rejected = (value) => {
      try {
        step(generator.throw(value));
      } catch (e) {
        reject(e);
      }
    };
    var step = (x) => x.done ? resolve(x.value) : Promise.resolve(x.value).then(fulfilled, rejected);
    step((generator = generator.apply(__this, __arguments)).next());
  });
};

// src/util/get-response.ts
var get = (response, expectedCode, doNotExit = false) => __async(void 0, null, function* () {
  let res = null;
  if (![204, 303].includes(expectedCode)) {
    res = yield response.json();
  }
  if (response.status !== expectedCode) {
    if (res === null) {
      res = yield response.json();
    }
  }
  return res;
});
var get_response_default = get;
export {
  get_response_default as default
};
//# sourceMappingURL=get-response.mjs.map