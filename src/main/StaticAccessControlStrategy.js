'use strict'

const Enumeration = require('@northscaler/enum-support')

const StaticAccessControlStrategy = Enumeration.new({
  name: 'StaticAccessControlStrategy',
  values: ['GRANT', 'DENY', 'PERMIT']
}, {
  /**
   * @deprecated use `permits()`
   * @see StaticAccessControlStrategy#permits
   */
  grants () {
    return this === StaticAccessControlStrategy.GRANT || this === StaticAccessControlStrategy.PERMIT
  },

  denies () {
    return this === StaticAccessControlStrategy.DENY
  },

  /**
   * @since 1.3.0
   */
  permits () {
    return this === StaticAccessControlStrategy.PERMIT || this === StaticAccessControlStrategy.GRANT
  }
})

module.exports = StaticAccessControlStrategy
