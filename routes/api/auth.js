const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs')
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config')
const { check, validationResult } = require('express-validator')

const User = require('../../models/User');

////////////////////////////////////////////////////////////////////////////
//       GET USER BY TOKEN
////////////////////////////////////////////////////////////////////////////

// @route   GET api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password'); // leave off the password from the returning data
        res.json(user)
    } catch (err) {
        console.error(err.message)
        res.status(500).send('Server Error')
    }
});


////////////////////////////////////////////////////////////////////////////
//       LOGIN USER BY EMAIL AND PASSWORD && GET TOKEN
////////////////////////////////////////////////////////////////////////////

// @route   POST api/auth
// @desc    Authenticate user & get token
// @access  Public
router.post('/', 
[
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
],
async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const { email, password } = req.body;

    try {
        // Check if user exists
        let user = await User.findOne({ email });

        if(!user) {
            return res
                .status(400)
                .json({ errors: [{msg: 'Invalid Credentials'}] });
        }

        // Check if password matches with the password in db
        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch) {
            return res
                .status(400)
                .json({ errors: [{msg: 'Invalid Credentials'}] });
        }

        // Generate & return jsonwebtoken
        const payload = {
            user: {
                id: user.id  // mongoose: id (mongodb: _id)
            }
        }

        jwt.sign(
            payload, 
            config.get('jwtSecret'),
            { expiresIn: 36000 }, // Optional. Long duration for dev. Don't forget to shorten for prod.
            (err, token) => {
                if(err) throw err;
                res.json({ token });
            }
            );
        
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server error')
    }

});

module.exports = router;