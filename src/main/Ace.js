'use strict'

const { GRANT, DENY, PERMIT } = require('./StaticAccessControlStrategy')
const DEFAULT_SAMENESS_TESTER = require('./SamenessTester')

/**
 * An access control entry, which binds together
 * * an **access control strategy**,
 * * a **principal**,
 * * a **securable**, and
 * * an **action**.
 *
 * You may also provide a **sameness tester function** to determine sameness amongst objects, defaulting to {@link Ace.testDefaultSameness}.
 */
class Ace {
  /**
   * A factory method for producing an {@link Ace} that statically permits the principal to take the action with respect to the securable.
   * @param {Object} arg The argument.
   * @param {AccessControlStrategy} arg.strategy The {@link Ace}'s strategy.
   * @param {any} arg.principal The {@link Ace}'s principal.
   * @param {any} arg.securable The {@link Ace}'s securable.
   * @param {any} arg.action The {@link Ace}'s action.
   * @param {SamenessTesterFn} [arg.samenessTesterFn] A function used to determine if two objects are equivalent, defaulting to {@link Ace.testDefaultSameness}.
   * @return {Ace}
   * @since 1.3.0
   */
  static permitting ({ principal, securable, action, samenessTesterFn } = {}) {
    return Ace.of({ strategy: PERMIT, principal, securable, action, samenessTesterFn })
  }

  /**
   * A factory method for producing an {@link Ace} that statically grants the action to the principal with respect to the securable.
   * @param {Object} arg The argument.
   * @param {AccessControlStrategy} arg.strategy The {@link Ace}'s strategy.
   * @param {any} arg.principal The {@link Ace}'s principal.
   * @param {any} arg.securable The {@link Ace}'s securable.
   * @param {any} arg.action The {@link Ace}'s action.
   * @param {SamenessTesterFn} [arg.samenessTesterFn] A function used to determine if two objects are equivalent, defaulting to {@link Ace.testDefaultSameness}.
   * @return {Ace}
   * @deprecated use Ace.permitting
   */
  static granting ({ principal, securable, action, samenessTesterFn } = {}) {
    return Ace.permitting(...arguments)
  }

  /**
   * A factory method for producing an {@link Ace} that statically denies the action to the principal with respect to the securable.
   * @param {Object} arg The argument.
   * @param {AccessControlStrategy} arg.strategy The {@link Ace}'s strategy.
   * @param {any} arg.principal The {@link Ace}'s principal.
   * @param {any} arg.securable The {@link Ace}'s securable.
   * @param {any} arg.action The {@link Ace}'s action.
   * @param {SamenessTesterFn} [arg.samenessTesterFn] A function used to determine if two objects are equivalent, defaulting to {@link Ace.testDefaultSameness}.
   * @return {Ace}
   */
  static denying ({ principal, securable, action, samenessTesterFn } = {}) {
    return Ace.of({ strategy: DENY, principal, securable, action, samenessTesterFn })
  }

  /**
   * A factory method for producing an {@link Ace} that uses the given strategy to grant or deny the action to or from the principal, respectively, with respect to the securable.
   * @param {Object} arg The argument.
   * @param {AccessControlStrategy} arg.strategy The {@link Ace}'s strategy.
   * @param {any} arg.principal The {@link Ace}'s principal.
   * @param {any} arg.securable The {@link Ace}'s securable.
   * @param {any} arg.action The {@link Ace}'s action.
   * @param {SamenessTesterFn} [arg.samenessTesterFn] A function used to determine if two objects are equivalent, defaulting to {@link Ace.testDefaultSameness}.
   * @return {Ace}
   */
  static of ({ strategy, principal, securable, action, samenessTesterFn } = {}) {
    return new Ace({ strategy, principal, securable, action, samenessTesterFn })
  }

  static testDefaultSameness (that, other) {
    return DEFAULT_SAMENESS_TESTER(that, other)
  }

  /**
   * Constructor that uses the given strategy to grant or deny the action to or from the principal, respectively, with respect to the securable.
   * @param {Object} arg The argument.
   * @param {AccessControlStrategy} arg.strategy The {@link Ace}'s strategy.
   * @param {any} arg.principal The {@link Ace}'s principal.
   * @param {any} arg.securable The {@link Ace}'s securable.
   * @param {any} arg.action The {@link Ace}'s action.
   * @param {SamenessTesterFn} [arg.samenessTesterFn] A function used to determine if two objects are equivalent, defaulting to {@link Ace.testDefaultSameness}.
   */
  constructor ({ strategy, principal, securable, action, samenessTesterFn = Ace.testDefaultSameness }) {
    this._principal = principal
    this._action = action
    this._securable = securable
    this._strategy = this._testSetStrategy(strategy)
    this._testSameness = samenessTesterFn

    Object.freeze(this)
  }

  get principal () {
    return this._principal
  }

  get action () {
    return this._action
  }

  get securable () {
    return this._securable
  }

  get strategy () {
    return this._strategy
  }

  _testSetStrategy (strategy) {
    if (
      (strategy?.permits && typeof strategy?.permits !== 'function') ||
      (strategy?.grants && typeof strategy?.grants !== 'function') ||
      (!strategy?.grants && !strategy?.permits) ||
      typeof strategy?.denies !== 'function'
    ) {
      throw new Error('invalid strategy given')
    }
    return strategy
  }

  /**
   * Determines if this Ace applies to the given principal, securable, and action.
   * @private
   */
  _applies ({ principal, securable, action }) {
    return (
      this.appliesToSecurable(securable) &&
      this.appliesToAction(action) &&
      (!this._principal || this._testSameness(this._principal, principal))
    )
  }

  /**
   * Returns whether this {@link Ace} permits and does not explicitly deny the given **principal** the **action** with respect to the given **securable**, given optional **data**.
   *
   * @param {AccessControlTuple} arg The argument to be deconstructed.
   * @param {any} arg.principal The principal in question.
   * @param {any} arg.action The action in question.
   * @param {any} arg.securable The securable in question.
   * @param {any} [arg.data] Optional contextual data.
   * @since 1.3.0
   */
  permits ({ principal, action, securable, data } = {}) {
    return (
      this._applies({ principal, securable, action }) &&
      !this._strategy.denies({ principal, action, securable, data }) &&
      (this._strategy.permits || this._strategy.grants).bind(this._strategy)({ principal, action, securable, data })
    )
  }

  /**
   * Returns whether this {@link Ace} grants and does not explicitly deny the given **principal** the **action** with respect to the given **securable**, given optional **data**.
   *
   * @param {AccessControlTuple} arg The argument to be deconstructed.
   * @param {any} arg.principal The principal in question.
   * @param {any} arg.action The action in question.
   * @param {any} arg.securable The securable in question.
   * @param {any} [arg.data] Optional contextual data.
   * @deprecated use Ace#permits
   */
  grants ({ principal, action, securable, data } = {}) {
    return this.permits(...arguments)
  }

  /**
   * Returns whether this {@link Ace} explicitly denies the given **principal** the **action** with respect to the given **securable**, given optional **data**.
   *
   * @param {AccessControlTuple} arg The argument to be deconstructed.
   * @param {any} arg.principal The principal in question.
   * @param {any} arg.action The action in question.
   * @param {any} arg.securable The securable in question.
   * @param {any} [arg.data] Optional contextual data.
   */
  denies ({ principal, action, securable, data } = {}) {
    return (
      this._applies({ principal, securable, action }) &&
      this._strategy.denies({ principal, action, securable, data })
    )
  }

  appliesToPrincipal (principal) {
    return !this._principal || this._testSameness(principal, this._principal)
  }

  appliesToAction (action) {
    return !this._action || this._testSameness(action, this._action)
  }

  appliesToSecurable (securable) {
    return !this._securable || this._testSameness(securable, this._securable)
  }

  appliesToStrategy (strategy) {
    strategy = strategy === GRANT ? PERMIT : strategy
    return this._testSameness(strategy, this._strategy)
  }
}

Ace.DEFAULT_SAMENESS_TESTER = DEFAULT_SAMENESS_TESTER

module.exports = Ace
