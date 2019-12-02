'use strict'

const Enumeration = require('@northscaler/enum-support')

const PrimitiveAction = Enumeration.new({
  name: 'PrimitiveAction',
  values: ['CREATE', 'REFERENCE', 'READ', 'UPDATE', 'DELETE', 'SECURE']
})

module.exports = PrimitiveAction
