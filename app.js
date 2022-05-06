const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const cors = require('cors');
const fileUpload = require('express-fileupload');



const allRoutes = require('./routes/allRoutes');
const authRoutes = require('./routes/authRoutes');

const app = express();

// view engine setup

app.use(logger('dev'));

app.use(cors({
  origin: ["http://localhost:3000"],
  methods: ["GET", "POST"],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(fileUpload());



app.use(allRoutes);
app.use(authRoutes);

module.exports = app;
