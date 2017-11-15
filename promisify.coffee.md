Promisify
---------

Wraps a callback-based method `method` (a function) on object `obj` with optional arguments `args` and last argument a Node.js-type callback, into a Promise.

This is _not_ equivalent to Bluebird's Promisify, but we don't _need_ Bluebird's version.

    promisify = (obj,method,args...) ->
      new Promise (resolve,reject) ->
        method.call obj, args..., (err,res) ->
          if err?
            reject err
          else
            resolve res

    module.exports = promisify
