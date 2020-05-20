'use strict'

const { DENY, PERMIT } = require('./StaticAccessControlStrategy')
const Ace = require('./Ace')

/**
 * Access control list
 */
class Acl {
  constructor () {
    this._aces = []
  }

  /**
   * Returns whether all of the given actions are granted amongst the given principals against the given securable, and none of the principals are denied any of the actions.
   *
   * @param {Object} arg The argument to be deconstructed.
   * @param {any[]} arg.principals The **principals** that must individually not be explicitly denied `arg.actions` and that must collectively be granted `arg.actions`.
   * @param {any[]} arg.actions The actions none of which must be denied from individual `arg.principals` and all of which must be collectively granted amongst `arg.principals`.
   * @param {any} arg.securable The thing access to which is being governed.
   * @param {any} [arg.data] Any contextual information needed for the access control decision; passed into each ACE's `denies` & `grants` methods.
   * @return {boolean} Whether the `arg.principals` are collectively granted.
   * @type {MultiGrantsDecisionFn}
   * @since 1.3.0
   */
  permits ({ principals, actions, securable, data }) {
    principals = this._ensureArray(principals)
    actions = this._ensureArray(actions)

    const aces = this._findApplicableAces({ principals, actions, securable })
    if (this._denies({ principals, actions, securable, data, aces })) return false
    // else no one's denied, so check for grants

    // start with each unique action not being granted
    const grantsByAction = actions.reduce((grants, action) => {
      grants[action] = false
      return grants
    }, {})

    aces.forEach(ace => {
      principals.forEach(principal => {
        actions.forEach(action => {
          // skip if action is already granted
          if (!grantsByAction[action] && ace.grants({ principal, action, securable, data })) {
            grantsByAction[action] = true
          }
        })
      })
    })

    return !actions.map(action => grantsByAction[action]).includes(false) // whether any actions weren't granted
  }

  /**
   * Returns whether all of the given actions are granted amongst the given principals against the given securable, and none of the principals are denied any of the actions.
   *
   * @param {Object} arg The argument to be deconstructed.
   * @param {any[]} arg.principals The **principals** that must individually not be explicitly denied `arg.actions` and that must collectively be granted `arg.actions`.
   * @param {any[]} arg.actions The actions none of which must be denied from individual `arg.principals` and all of which must be collectively granted amongst `arg.principals`.
   * @param {any} arg.securable The thing access to which is being governed.
   * @param {any} [arg.data] Any contextual information needed for the access control decision; passed into each ACE's `denies` & `grants` methods.
   * @return {boolean} Whether the `arg.principals` are collectively granted.
   * @type {MultiGrantsDecisionFn}
   * @deprecated use Acl#permits
   */
  grants ({ principals, actions, securable, data }) {
    return this.permits(...arguments)
  }

  /**
   * Returns whether any of the given principals are explicitly denied any of the given actions against the given securable.
   * @param {Object} arg The argument to be deconstructed.
   * @param {any[]} arg.principals The principals that are individually tested for explicit denial of any of the `arg.actions`.
   * @param {any[]} arg.actions The actions none of which must be explicitly denied from `arg.principals`.
   * @param {any} arg.securable The thing access to which is being governed.
   * @param {any} [arg.data] Any contextual information needed for the access control decision; passed to each ACE's `denies` & `grants` methods.
   * @return {boolean} Whether any of the `arg.principals` are denied any of the (@param actions}.
   */
  denies ({ principals, actions, securable, data }) {
    principals = this._ensureArray(principals)
    actions = this._ensureArray(actions)

    return this._denies({
      principals,
      actions,
      securable,
      data,
      aces: this._findApplicableAces({ principals, actions, securable })
    })
  }

  _denies ({ principals, actions, securable, data, aces }) {
    principals = this._ensureArray(principals)
    actions = this._ensureArray(actions)

    for (const ace of aces) {
      for (const principal of principals) {
        for (const action of actions) {
          if (ace.denies({ principal, action, securable, data })) return true
        }
      }
    }
    return false
  }

  _findApplicableAces ({ principals, actions, securable }) {
    return this._aces.filter(ace => {
      let applies = false
      for (const p of principals) {
        if (ace.appliesToPrincipal(p)) {
          applies = true
          break
        }
      }
      if (!applies) return false

      applies = false
      for (const a of actions) {
        if (ace.appliesToAction(a)) {
          applies = true
          break
        }
      }
      if (!applies) return false

      return ace.appliesToSecurable(securable)
    })
  }

  _ensureArray (it) {
    return Array.isArray(it) ? it : [it]
  }

  /**
   * @since 1.3.0
   */
  permit ({ principal, securable, action }) {
    return this.secure({ strategy: PERMIT, principal, securable, action })
  }

  /**
   * @deprecated use Acl#permit
   */
  grant ({ principal, securable, action }) {
    return this.permit(...arguments)
  }

  /**
   * @since 1.3.0
   */
  unpermit ({ principal, securable, action }) {
    return this.unsecure({ strategy: PERMIT, principal, securable, action })
  }

  /**
   * @deprecated use Acl#unpermit
   */
  ungrant ({ principal, securable, action }) {
    return this.unpermit(...arguments)
  }

  deny ({ principal, securable, action }) {
    return this.secure({ strategy: DENY, principal, securable, action })
  }

  undeny ({ principal, securable, action }) {
    return this.unsecure({ strategy: DENY, principal, securable, action })
  }

  /**
   * Adds an access control entry (ACE).
   * Idempotent if the ACE already exists.
   *
   * @param {Object} arg The argument to be deconstructed.
   * @param {AccessControlStrategy} arg.strategy The ACE's strategy.
   * @param {any} arg.principal The ACE's principal.
   * @param {any} arg.securable The ACE's securable.
   * @param {any} arg.action The ACE's action.
   * @return {Acl} This ACL in order to support a builder pattern.
   */
  secure ({ strategy, principal, securable, action }) {
    return this._secure({ strategy, principal, securable, action, add: true })
  }

  /**
   * Removes an access control entry (ACE).
   * Idempotent if the ACE already absent.
   *
   * @param {Object} arg The argument to be deconstructed.
   * @param {AccessControlStrategy} arg.strategy The ACE's strategy.
   * @param {any} arg.principal The ACE's principal.
   * @param {any} arg.securable The ACE's securable.
   * @param {any} arg.action The ACE's action.
   * @return {Acl} This ACL in order to support a builder pattern.
   */
  unsecure ({ strategy, principal, securable, action }) {
    return this._secure({ strategy, principal, securable, action, add: false })
  }

  _secure ({ strategy, principal, securable, action, add = true }) {
    const index = this._aces.findIndex(ace =>
      ace.appliesToPrincipal(principal) &&
      ace.appliesToAction(action) &&
      ace.appliesToStrategy(strategy) &&
      (securable ? ace.appliesToSecurable(securable) : true)
    )

    if (add && index === -1) { // not found, so add, else ignore because it's already there
      this._aces.push(Ace.of({ strategy, principal, securable, action }))
    } else if (!add && index !== -1) { // found, so remove, else ignore because it's already not there
      this._aces.splice(index, 1)
    }

    return this
  }
}

module.exports = Acl
