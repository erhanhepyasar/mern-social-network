const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = function(req, res, next) {
    // Get token from header
    const token = req.header('x-auth-token');

    // Check if not token
    if(!token) {
        return res.status(401).json({ msg: 'No token. Authorization denied'})
    }

    try {
        // Verify token
       const decoded = jwt.verify(token, config.get('jwtSecret')) ;
        
       // Get user data from decoded token
       req.user = decoded.user;
       next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid'});
    }
}