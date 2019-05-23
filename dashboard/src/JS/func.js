const { dialog } = require('electron').remote
const electron = require('electron').remote
const fs = require('fs');
const net = require('net');
const path = require('path')
const crypto = require('crypto');
const algorithm = 'aes-128-cbc';
const serverURL = "0.tcp.ngrok.io"
const serverPort = "16801"
var password = "password"
var iv, salt
let w = electron.getCurrentWindow()
var connected = false
var socket = new net.Socket(writable=true)
var max = '□'
var min = '◱'
var a
socket.on('data', function(data) {
  data = new TextDecoder("utf-8").decode(data);
  data = decrypt(data)
  i = data.indexOf("#")
  if(i>0) {
    data = data.substring(0,i)
  }
  response = JSON.parse(data)
  console.log(a=response)
  for (var i = 1; i > 0; i++) {
    if(!response.hasOwnProperty(i)){
      break
    } else if (!response[i]) {
      document.getElementById("node"+i).innerHTML = ""
    } else {
      document.getElementById("node"+i).innerHTML = 'Server Status: <div class="status" id="node'+i+'-status"> ●●●</div>Online'
    }
  }
  
  unload()
});
function connectTCP(host, port){
  socket.connect(port, host, function(){connected=true;update()})
}
function load(){
  document.getElementById("loading").style.visibility = "visible"
}
function unload(){
  document.getElementById("loading").style.visibility = "hidden"
}
function tcpSend(message, ret){
  socket.write(message)
}
function update() {
  if(connected) {
    load()
    encrypt("update")
  }
}
var out
async function sendFile(node) {
  fileNames = dialog.showOpenDialog({title:"file"})
  console.log(await fs.readFile(fileNames[0], function(err,ret) {
    if(err) {
      alert(err);
      return;
    }
    out = ret;
    f = "file" + node + fileNames[0]+","+String(out)
     encrypt(f)
  }))
}
function reconnect() {
  load()
  socket.destroy()
  connectTCP(serverURL,serverPort)
}
function encrypt(message){
  crypto.randomBytes(8, (err, buf) => {
        if (err) throw err;
        salt = buf
        crypto.randomBytes(16, (err, buf) => {
          if (err) throw err;
          iv = buf
          key = crypto.pbkdf2Sync((password), (salt), 100, 16, 'sha256');
          en = crypto.createCipheriv(algorithm, key, iv);
          result = en.update(message, 'utf8', 'hex');
          result += en.final("hex")
          rv = (iv.toString('hex') + ":" + result + ":" + salt.toString('hex'))
          console.log(rv)
          tcpSend(rv)
        });
    });
}
function decrypt(message) {
  console.log(message)
  let [i, encrypted, s] = splitMessage(message)
  iv = new Uint8Array(Buffer.from(i, "hex"));
  salt = new Uint8Array(Buffer.from(s, 'hex'));
  key = crypto.pbkdf2Sync((password), (salt), 100, 16, 'sha256');
  console.log(key)
  decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAutoPadding(false);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted
}
var resize = document.getElementById("resize");
function resizeWindow() {
  current = resize.innerText;
  resize.innerText==max?w.maximize():w.unmaximize();
  resize.innerText=resize.innerText==max?min:max;
  scroll()
}
w.on('enter-full-screen', () => {
  resize.innerText=min
  scroll()
});
w.on('maximize', () => {
  resize.innerText=min
  scroll()
});
w.on('leave-full-screen', () => {
  resize.innerText=max
  scroll()
});
w.on('unmaximize', () => {
  resize.innerText=max
  scroll()
});
function startUp(){
  w.maximize();
}
function splitMessage(m){
  return m.split(":")
}
//setInterval(update, 5000)