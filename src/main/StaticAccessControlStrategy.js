'use strict'

const Enumeration = require('@northscaler/enum-support')

const StaticAccessControlStrategy = Enumeration.new({
  name: 'StaticAccessControlStrategy',
  values: ['GRANT', 'DENY']
}, {
  grants () {
    return this === StaticAccessControlStrategy.GRANT
  },

  denies () {
    return this === StaticAccessControlStrategy.DENY
  }
})

module.exports = StaticAccessControlStrategy
