module.exports = {
  up: (queryInterface, DataTypes) => queryInterface.addColumn('Books', 'chapeu', {
    allowNull: false,
    type: DataTypes.INTEGER,
  }),

  down: queryInterface => queryInterface.dropColumn('Books', 'chapeu'),
};
