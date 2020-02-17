'use strict'

// This file simply contains the JSDoc definitions of an AccessControlStrategy and related functions.

/**
 * Returns whether the given `action` is granted to the given `principal` with respect to the given `securable`, and that the `principal` is not _explicitly denied_ the `action`, given optional `data`.
 *
 * @function GrantsDecisionFn
 * @param {Object} arg The argument to be deconstructed.
 * @param {any} arg.principal The **principal** that must be granted and not explicitly denied the `arg.action` with respect to the `arg.securable`, given optional `arg.data`.
 * @param {any} arg.action The **action** being taken by the `arg.principal` with respect to the `arg.securable`, given optional `arg.data`.
 * @param {any} arg.securable The **securable** access to which is being controlled.
 * @param {any} [arg.data] Optional, arbitrary data that may be used to make an access control decision.
 * @return {boolean} Whether `arg.principal` is granted the `arg.action` with respect to the `arg.securable` given `arg.data`.
 */

/**
 * Returns whether the given `action` is explicitly denied from the given `principal` with respect to the given `securable` and given optional `data`.
 *
 * @function DeniesDecisionFn
 * @param {Object} arg The argument to be deconstructed.
 * @param {any} arg.principal The **principal** being tested for explicit denial of the `arg.action` with respect to the `arg.securable`, given optional `arg.data`.
 * @param {any} arg.action The **action** being taken by the `arg.principal` with respect to the `arg.securable`, given optional `arg.data`.
 * @param {any} arg.securable The thing access to which is being controlled.
 * @param {any} [arg.data] Optional, arbitrary data that may be used to make an access control decision.
 * @return {boolean} Whether `arg.principal` is denied the `arg.action` with respect to the `arg.securable` given `arg.data`.
 */

/**
 * @typedef AccessControlStrategy
 * @type {Object}
 * @property {GrantsDecisionFn} grants
 * @property {DeniesDecisionFn} denies
 */

/**
 * @typedef AccessControlTuple
 * @type {Object}
 * @property {any} principal The principal.
 * @property {any} action The action.
 * @property {any} securable The securable.
 * @property {any} [data] Optional contextual data.
 */

/**
 * Returns whether all of the given actions are granted amongst the given principals with respect to the given securable, and none of the principals are denied any of the actions.
 *
 * @function MultiGrantsDecisionFn
 * @param {Object} arg The argument to be deconstructed.
 * @param {any[]} arg.principals The **principals** that must individually not be explicitly denied any `arg.actions` and that must collectively be granted `arg.actions` with respect to `arg.securable`.
 * @param {any[]} actions The **actions** _none_ of which must be denied from _any_ of the `arg.principals`, and _all_ of which must be collectively granted amongst `arg.principals`.
 * @param {any} securable The thing access to which is being controlled.
 * @param {any} [data] Any contextual information needed for the access control decision; passed into each ACE's `denies` & `grants` methods.
 * @return {boolean} Whether the `arg.principals` are collectively granted and none of which are explicitly denied.
 */

/**
 * Returns whether any of the given principals are explicitly denied any of the given actions against the given securable.
 *
 * @function MultiDeniesDecisionFn
 * @param {Object} arg The argument to be deconstructed.
 * @param {any[]} arg.principals The **principals** that may be explicitly denied any `arg.actions` with respect to `arg.securable`, given optional `arg.data`.
 * @param {any[]} actions The **actions** which may be denied from _any_ of the `arg.principals`.
 * @param {any} securable The thing access to which is being controlled.
 * @param {any} [data] Any contextual information needed for the access control decision; passed into each ACE's `denies` & `grants` methods.
 * @return {boolean} Whether any of the `arg.principals` are denied any of the `arg.`actions`.
 */
