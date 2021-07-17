module.exports = {
  timeout: 10 * 60 * 1000, // 10 minutes
  exit: true,
  parallel: false, // Can't do parallel tests because of ETH testnet snapshot/restoring
}
