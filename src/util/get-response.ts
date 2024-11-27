const get = async (response: Response, expectedCode: number, doNotExit: boolean = false): Promise<any> => {
  let res = null
  // Handle case of No Content
  if (![204, 303].includes(expectedCode)) {
    res = await response.json()
  }
  if (response.status !== expectedCode) {
    if (res === null) {
      res = await response.json()
    }
    // ux.log('⚠️ ' + chalk.red(res.message || res.error))
    // if (!doNotExit) {
    //   exit(1)
    // }
  }
  return res
}
export default get
