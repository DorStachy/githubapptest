function info(message, context = {}) {
  const serialized = JSON.stringify(context);
  console.log(`[INFO] ${message} ${serialized}`);
}

function error(message, context = {}) {
  const serialized = JSON.stringify(context);
  console.error(`[ERROR] ${message} ${serialized}`);
}

module.exports = { info, error };
