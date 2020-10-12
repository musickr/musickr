let base_url = "http://127.0.0.1/api";
let version  = '' 
let request = (api, data = [], method = "GET") => {
  wx.showLoading({
    title: '请求中...',
  })
  return new Promise(function(resolve, reject) {
    // 异步处理
    wx.request({
      url: base_url + version + "/" + api,
      method:method,
      data:data,
      header:{
        Accept: "application/json",
        token:wx.getStorageSync('token')
      },
      success:res=>{
        switch(res.statusCode){
          case 200:
            resolve(res.data);
            break;
          case 401:
            wx.navigateTo({
              url: '/pages/login/login',
            })
            break;
          case 403:
            console.log(res)
            wx.showModal({
              title: '提示',
              content:res.data.msg,
              confirmText:'去登陆',
              success (res) {
                if (res.confirm) {
                  wx.navigateTo({
                    url: '/pages/login/login',
                  })
                } else if (res.cancel) {
                  return false;
                }
              }
            })
            break;
          default:
            wx.showModal({
              title:'提示',
              content: res.data.msg,
            })
        }
      },
      fail:error=>{
        wx.showModal({
          title:'提示',
          content: '网络出错',
        })
      },
      complete:resp=>{
        wx.hideLoading({
          success: (res) => {},
        })
      }
    })
    // 处理结束后、调用resolve 或 reject
})
}
const get = (api,data=[]) => {
  return request(api,data,"GET")
}
const post = (api,data=[]) => {
  return request(api,data,"POST")
}

module.exports = {
  get,post
}