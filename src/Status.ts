export default class Status {
    isAuth() {
        const accessToken = localStorage.getItem('accessToken')
        const refreshToken = localStorage.getItem('refreshToken')
        return !(!accessToken && !refreshToken);
    }
}
