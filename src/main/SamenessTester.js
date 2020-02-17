'use strict'

/**
 * @function SamenessTesterFn
 * @param that Something being tested for sameness as {@param other}.
 * @param other Something being tests for sameness as {@param that}.
 * @return {boolean} Whether the two things are considered to be the same.
 */
function testSameness (that, other) {
  return that === other ||
    (that?._id && that?._id === other?._id) ||
    (that?.id && that?.id === other?.id) ||
    ((typeof that?.identifies === 'function') && that?.identifies(other))
}

module.exports = testSameness
