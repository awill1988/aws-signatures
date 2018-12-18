/* File: gulpfile.js */

// grab our packages
const gulp   = require('gulp');
const run = require('gulp-run');


// configure the jshint task
gulp.task('watch', function() {
  return gulp.watch('src/**/*.ts*', gulp.series('compile'));
});

gulp.task('compile', function() {
  return run('npm run compile')
    .exec();
});

// define the default task and add the watch task to it
gulp.task('default', gulp.series('compile', 'watch'));