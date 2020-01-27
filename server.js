
var express = require('express');
var serveStatic = require('serve-static');
var bodyParser = require('body-parser')
var cookieParser = require('cookie-parser');
var mongo = require('mongodb').MongoClient;
var unless = require('express-unless');
var session = require('client-sessions');
var csurf = require('csurf');

var config = require('./server.conf');

var app = express();
app.use(bodyParser.json());	
app.use(bodyParser.urlencoded({   
	extended: true
}));
app.use(cookieParser());

app.use(serveStatic(__dirname + '/public'));	

app.use(session({
	cookieName: 'session',
	secret: config.sessionSecret,
	duration: 60 * 60 * 1000 * 24,	
	cookie: {
		httpOnly: false,
		maxAge: 1000 * 60 * 15, 
	}
}));

//Usar el puerto 9002
app.listen(9002, function(){
	if(process.env.NODE_ENV === undefined)
		process.env.NODE_ENV = '...';
	console.log("Servidor activo en localhost", this.address().port, process.env.NODE_ENV);
});

//Este codigo es VULNERABLE
function authenticate(user, pass, req, res){
	mongo.connect('mongodb://localhost:27017/ej4_bd', function(err, db){
		if(err){ 
			console.log('Error en la conexión');
			return err;
		}
		db.collection('usuarios').findOne({usuario: user, clave: pass},function(err, result){
			if(err){
				console.log('Error en la sentencia');
				return err;
			}
			if(result !== null){
				req.session.authenticated = true;
				res.redirect('/');
			}
			else
				res.redirect('/login?user='+user);
		});
		
	});	
}

var queryMongo = function(res, database, collectionName, field, value){

	mongo.connect('mongodb://localhost:27017/'+database, function(err, db){
		if(err){ 
			console.log('Error en la conexión');
			return err;
		}

		var query = {}

		query[field] = value;

		db.collection(collectionName).find(query).toArray(function(err, result){
			if(err){
				console.log('Error');
				return err;
			}
			res.send(result);
		});
	});
}

var isLoggedIn = function(req, res, next){
	if(req.session.authenticated)
		next();
	else
		res.redirect('/login');	
}

isLoggedIn.unless = unless;


app.use(isLoggedIn.unless({path: /^(?!\/secure).*/}));

app.get('/', isLoggedIn, function(req, res){
	res.sendFile('./index.html', {root: __dirname})
});

app.get('/login', function(req, res){
	res.sendFile('./login.html', {root: __dirname})
});

app.post('/login', function(req, res){
	authenticate(req.body.user, req.body.pass, req, res);
});

app.use(csurf({
	cookie: true,
}));

app.use(function(req, res, next){
	res.cookie('XSRF-TOKEN', req.csrfToken());
	next();
});

app.use(function (err, req, res, next) {
	if (err.code !== 'EBADCSRFTOKEN') return next(err);
	res.status(403)
	res.send('form tampered with')
});

