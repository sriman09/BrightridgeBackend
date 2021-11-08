const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;

module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    logout,
    audit
};

async function authenticate({ username, password, clientIp, loginTime, logoutTime }) {
    const user = await User.findOne({ username });
    if (user && !logoutTime && bcrypt.compareSync(password, user.hash)) {
        user.loginTime = loginTime; user.logoutTime = logoutTime;
        user.clientIp = clientIp;
        user.save();
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        return {
            ...userWithoutHash,
            token
        };
    } else if (user && logoutTime) {
        user.logoutTime = logoutTime;
        user.save();
        return {
            status: 200,
            message: "User Logged Out Successfully"
        }
    }
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    userParam.clientIp = 'NA';
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);
    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }
    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}

async function logout(id) {
    const user = await User.findById(id);
    // validate
    if (!user) throw 'User not found';

    user.logoutTime = Date.now();

    await user.save();
}

async function audit(id) {
    const user = await User.findById(id);
    if (!user) throw 'User not found';
    if (user.role !== 'Auditor') throw { name: 'InvalidRole', message: 'User Not Authorized' };

    return await getAll();

}