# @northscaler/acl

This library allows you to maintain security information in access control lists (ACLs).

There are four elements required in the determination of access:
* __principal__:  The actor, user or system attempting to perform some action on a securable.
* __securable__:  The thing being secured.
* __action__:  The action being performed on a securable.
This library defines a minimal set of [primitive actions](src/main/PrimitiveAction.js), but you can define your own.
* __access control entry__:  the binding of the principal, securable and action together along with the "permitted" (or "denied") boolean, or some other strategy.
Some systems call this a "permission", a "right" or a "grant" in the positive sense, and a "denial", an "antipermission", or a "negative permission" in the negative sense.
We use the more general term "access control entry", often abbreviated ACE (similar to ACL), which can mean either a permission or a denial.

The primary export of this module is a class called `Acl`, which has interrogation methods `permits` & `denies`, as well as mutating methods like `permit`, `unpermit`, `deny`, `undeny`, or, the more general `secure` & `unsecure` methods.

>NOTE: In this implementation, a single denial vetoes any number of permissions, and the absence of any permissions denies.

It supports declarative or static security algorithms (think "permitted" or "denied" as a simple boolean), as well as algorithmic or dynamic security algorithms (think "permitted if today is a weekday", "denied if the balance is greater than 10000", or similar).

## TL;DR
See the tests in [`src/test/unit/Acl.spec.js`](src/test/unit/Acl.spec.js) for usage.

## Simple, declarative strategy example
This is simply one of the tests.
```javascript
    const acl = new Acl()                                                     // 1
    const principal = uuid()                                                  // 2
    const securable = uuid()                                                  // 3
    const action = uuid()                                                     // 4

    acl.permit({ principal, securable, action })                               // 5

    expect(acl.permits({ principals: principal, actions: action, securable })) // 6
      .to.equal(true)
    expect(acl.denies({ principals: principal, actions: action, securable }))
      .to.equal(false)

    acl.unpermit({ principal, securable, action })                             // 7

    expect(acl.permits({ principals: principal, actions: action, securable })) // 8
      .to.equal(false)
    expect(acl.denies({ principals: principal, actions: action, securable }))
      .to.equal(false)

    acl.deny({ principal, securable, action })                                // 9

    expect(acl.permits({ principals: principal, actions: action, securable })) // 10
      .to.equal(false)
    expect(acl.denies({ principals: principal, actions: action, securable }))
      .to.equal(true)

    acl.undeny({ principal, securable, action })                              // 11

    expect(acl.permits({ principals: principal, actions: action, securable })) // 12
      .to.equal(false)
    expect(acl.denies({ principals: principal, actions: action, securable }))
      .to.equal(false)
```

1. Creates a new access control list.
1. A principal.
This could be either an id _referring_ to a principal as in this example, or an actual principal object.  Up to you.
1. A securable.
This could be either an id _referring_ to a securable as in this example, or an actual securable object.  Up to you.
1. An action.
This could be anything you want, from one of the [primitive actions](src/main/PrimitiveAction.js), to a method name.  Again, up to you.
1. Instructs the ACL to permit the given principal the ability to take the given action against the given securable.
1. Interrogates the ACL to ensure that the permission took place correctly.
1. Instructs the ACL to remove the permission that was previously given.
Note that this is not an explicit denial; it is only the removal of the permission.
1. Interrogates the ACL to ensure that the removal of the permission took place correctly.
1. Instructs the ACL to explicitly deny from given principal the ability to take the given action against the given securable.
1. Interrogates the ACL to ensure that the denial took place correctly.
1. Instructs the ACL to remove the denial that was previously given.
1. Interrogates the ACL to ensure that the undenial took place correctly.

## Example with dynamic strategy

This is taken from the test ['should work with a custom strategy'](src/test/unit/Ace.spec.js#L57).
It shows that you can use arbitrarily complex logic to make access control decisions.
This example uses individual person's names, but they could just as easily be role type names.
The goal is to ensure that only the right principals can close securables with balances (like accounts), so the action is `'close'`.

```javascript
    const sally = 'sally'
    const john = 'john'
    const felix = 'felix'

    const close = 'close'

    class Strategy {                                        // 1
      constructor (hiThreshold, loThreshold) {              // 2
        this.hiThreshold = hiThreshold
        this.loThreshold = loThreshold
      }

      permits ({ principal, action, securable }) {           // 3
        switch (action) {
          case close:
            switch (principal) {
              case sally:
                return true                                 // 4
              case john:
                return securable.balance < this.hiThreshold // 5
              default:
                return securable.balance < this.loThreshold // 6
            }
        }
      }

      denies ({ principal, action, securable }) {           // 7
        switch (action) {
          case close:
            switch (principal) {
              case felix:                                   // 8
                return securable instanceof Account
              default:                                      // 9
                return false
            }
        }
      }
    }

    // see rest of test for assertions
```

1. Declare a strategy class.
The only requirements are that it has `permits` & `denies` methods.
1. Create a parameterized constructor so that strategy class is more flexible.
1. Define the permission logic.
We'll assume that the only securable type being passed in is an `Account`.
1. In this case, principal `sally` is always permitted to `close` any account.
1. `john` can close medium-valued accounts.
1. Everyone can close low-valued accounts.
1. This is the other method required by an access control strategy to determine if a principal is _explicitly denied_ from taking the given action against the given securable.
Here, we're only using the principal & action to make the determination.
1. Some time ago, we must've determined that `felix` is unfortunately prone to hitting "enter" before thinking things through, so we have effectively barred him from closing _any_ accounts.
Even though he's effectively permitted the ability to close a low-value account by virtue of the `permits` method, we're vetoing that capability here, because a single denial vetoes _all_ permits.
1. No one else is explicitly denied the ability to close an account.
