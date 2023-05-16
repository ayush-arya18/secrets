require('dotenv').config();
const express=require('express');
const bodyParser=require('body-parser');
const ejs=require('ejs');
const mongoose=require('mongoose');
const session=require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const GoogleStrategy=require('passport-google-oauth20').Strategy;
const findOrCreate=require('mongoose-findorcreate');
const _=require('lodash');
const app=express();

app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine','ejs');
app.use(session({
    secret: 'our little secret ',
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/cookieDB');
const cookiesSchema=new mongoose.Schema({
    username:String,
    password:String,
    googleId:String,
    secret:String
});
cookiesSchema.plugin(passportLocalMongoose);
cookiesSchema.plugin(findOrCreate);
const cookieModel=mongoose.model('cookieModel',cookiesSchema);

passport.use(cookieModel.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    cookieModel.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
))

app.get("/",function(req,res){
    res.render('home');
});
app.get("/auth/google",
    passport.authenticate('google',{scope:['profile']})
);
app.get('/auth/google/secret',
    passport.authenticate('google',{failureRedirect:'/login'}),
    function(req,res){
        res.redirect('/secrets');
    });
app.get('/login',function(req,res){
    res.render('login');
});
app.get('/register',function(req,res){
    res.render('register');
});
app.get("/secrets",function(req,res){
    if(req.isAuthenticated()){
        cookieModel.find().then(foundItems=>{
            if(foundItems){
                res.render('secrets',{usersWithSecrets:foundItems});
            }
        });
    }
    else{
        res.render('login');
    }
});
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render('submit');
    }
    else{
        res.render('login');
    }
});
app.get('/logout',function(req,res){
    req.logout();
    res.redirect("/");
});

app.post('/register',function(req,res){
    cookieModel.register({username:req.body.username}, req.body.password,function(err, user){
        if(err){
            console.log(err);
            res.redirect('/register');
        }
        else{
            passport.authenticate('local')(req,res,function(){ //we are sending a cookie to the borwser and asking it to hold on it 
                res.redirect("/secrets");
            });
        }
    });
});
app.post("/login",function(req,res){
    const data=new cookieModel({
        username:req.body.username,
        password:req.body.password
    });
    req.login(data,function(err){
        if(err){
            console.log(err);
            res.redirect('login');
        }
        else{
            passport.authenticate('local')(req,res,function(){
                res.redirect('/secrets');
            });
        }
    });
});
app.post('/submit',function(req,res){
    const userSecret=req.body.secret;
    cookieModel.findById(req.user.id).then(found=>{
        if(found){
            found.secret=userSecret;
            found.save();
            res.redirect('/secret');
        }
        else{
            res.redirect('login');
        }
    });
});

app.listen(3000,function(){
    console.log('server started on port 3000');
});