/* eslint-disable no-param-reassign */
const bcrypt = require('bcryptjs');
const { User } = require('../models');

module.exports = {
  signin: (req, { render }) => render('auth/signin'),

  signup: (req, { render }) => render('auth/signup'),

  async register({ body, flash }, { redirect }, next) {
    try {
      const { email } = body;
      if (await User.findOne({ where: { email } })) {
        flash('error', 'E-mail já cadastrado');
        return redirect('back');
      }

      const password = await bcrypt.hash(body.password, 5);
      await User.create({ ...body, password });
      flash('success', 'Cadastro realizado com sucesso!');
      return redirect.redirect('/');
    } catch (err) {
      return next(err);
    }
  },

  async authenticate({ body, flash, session }, { redirect }, next) {
    try {
      const { email, password } = body;

      const user = await User.findOne({ where: { email } });

      if (!user) {
        flash('error', 'Usuário não cadastrado.');
        return redirect('back');
      }

      if (!(await bcrypt.compare(password, user.password))) {
        flash('error', 'Senha incorreta');
        return redirect('back');
      }

      session.user = user;

      session.save(() => {
        redirect('app/dashboard');
      });
    } catch (err) {
      return next(err);
    }
  },

  signout: ({ session }, { redirect }) => session.destroy(() => redirect('/'))
};
