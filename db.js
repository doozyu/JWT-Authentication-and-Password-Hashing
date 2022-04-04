const Sequelize = require('sequelize');
const { STRING } = Sequelize;
const config = {
  logging: false,
};
const jwt = require('jsonwebtoken');
const secret = process.env.JWT;
const bcrypt = require('bcrypt');

const saltRounds = 10;

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || 'postgres://localhost/acme_db',
  config
);

const User = conn.define('user', {
  username: STRING,
  password: STRING,
});

const Note = conn.define('note', {
  text: STRING,
});

Note.belongsTo(User);
User.hasMany(Note);

User.beforeCreate(async (user) => {
  const hashedPW = await bcrypt.hash(user.password, saltRounds);
  user.password = hashedPW;
});

User.byToken = async (token) => {
  try {
    const userToken = await jwt.verify(token, secret);
    if (userToken) {
      const user = await User.findByPk(userToken.userId);
      if (user) {
        return user;
      }
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
    },
  });
  if (bcrypt.compare(password, user.password)) {
    const token = await jwt.sign({ userId: user.id }, secret);
    return token;
  }
  const error = Error('bad credentials');
  error.status = 401;
  throw error;
};

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw' },
    { username: 'moe', password: 'moe_pw' },
    { username: 'larry', password: 'larry_pw' },
  ];
  const notes = [
    { text: 'Some random text for this note.', userId: 1 },
    { text: 'Some other text for another note.', userId: 2 },
    { text: 'Even more text for a third note.', userId: 2 },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  await Promise.all(notes.map((note) => Note.create(note)));
  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
    Note,
  },
};
