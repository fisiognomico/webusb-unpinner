const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require('webpack');

module.exports = {
  entry: './src/index.ts',
  mode: process.env.NODE_ENV || 'development',
  devtool: process.env.NODE_ENV === 'production' ? 'source-map' : 'inline-source-map',
  devtool: 'inline-source-map',
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
    alias: {
      'android-package-sign-js': path.resolve(__dirname, '../android-package-sign-js'),
      'readline': false,
      'util': require.resolve('./polyfills/util.js'),
    },
    fallback: {
      "assert": false,
      "util": false,
    }
  },
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
    publicPath: '/'
  },
  externals: {
    'readline': 'readline',
    'net': 'net',
    'tls': 'tls',
    'fs': 'fs',
  },
  devServer: {
    static: path.join(__dirname, 'dist'),
    port: 9000,
    hot: true,
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './src/index.html'
    }),
    new webpack.DefinePlugin({
      __BACKEND_URL__: JSON.stringify(
        process.env.BACKEND_URL || 'http://localhost:3000'
      ),
      __NODE_ENV__: JSON.stringify(process.env.NODE_ENV || 'development'),
    }),
    new webpack.DefinePlugin({
      'global.debuglog': `(function(val) {
        return function(val) {
          return function(val) {};  // No-op function
        };
      })()`,
    }),
  ]
};
