'use strict';
function multer() { return { single: () => (req, res, next) => next() }; }
multer.memoryStorage = () => ({});
module.exports = multer;
