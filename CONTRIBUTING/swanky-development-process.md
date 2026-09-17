### Goals of the development process

* **Distribute Swanky knowledge.** If a question comes up about a part of Swanky, we should be able to answer it, even if the person who originally wrote the code is on PTO and attending the 17th annual Diet Soda Taste Test Competition. We want to ensure that Swanky knowledge is distributed among the team, rather than localized in one person.
* **Professional Development.** Working on Swanky should be a learning opportunity, where people learn new skills and techniques.
* **Improve Code.** More eyes on both design and implementation will catch issues earlier, and avoid making the same mistakes over again, in addition to improving APIs and making the code easier to use.

### Start with a Design

Before you start writing code, start by planning it out, ideally with the rest of team. This is especially important for wide-reaching changes or core components—if your change is going to affect every user of Swanky, you should make sure that they're on board before you make the change.

For most cases, design docs should live as Gitlab issues, to allow people to comment on them. When the design is implemented, the content of the design document (not necessarily verbatim) should be included in the merge request, ideally as part of the rustdoc for the module.

### Commit Practices / Invariants

In order to facilitate improved knowledge transfer, ease of code review and debugging and traceability of code changes, commits should have:

* A descriptive title: starting with a prefix that indicates the module or overarching feature that the commit pertains to, followed by a colon, ":", and finished with a brief summary
  * Use present tense / active voice for commit title
* Motivation and needed details about the change following the title (some commits may not need this, but more context is usually better)
* The following invariants:
  * All commits should compile, be formatted, and pass linting checks
  * The last commit in a branch should pass all Clippy checks

We have `pre-commit` and `pre-push` Git hooks found in `etc/hooks` that enforce the commit invariants listed above. Tell Git to use these hooks by copying them into the `.git/hooks` directory inside your cloned repository:

```bash
$> cp etc/hooks/* .git/hooks
```

There are additional recommended checks found in `pre-commit` and `pre-push` that can be uncommented out to enabled. See files for details.

### Merge Requests

_Every_ change to the Swanky git repo should be applied via a Merge Request. Before the change can be merged in, it must pass code review, and it must pass our Continuous Integration checks.

To quote Jonathan Daugherty:
> If a code review results in lots and lots of changes, that means early design review got missed. Code reviews shouldn't be hard; if they're hard, more [up-front work](#start-with-a-design) needed to happen.

#### Changelog

We want Swanky to be a vehicle to support the external research community. In order to do so, we need to not only publish/open-source the Swanky codebase, but also release it in a way that will enable external users to depend on Swanky.

As we continue to develop Swanky, we change and break public APIs. When this happens, it's important that we notify both internal and external users of APIs that changed, and how they can migrate to new APIs. This information is documented in our changelog.

Merge requests which make breaking changes to APIs should also update the changelog to add the a new entry with the changes.

#### Running CI Checks Locally

All MRs need to pass CI's checks. CI will, in addition to running Rust tests, also run a series of lints. It can be faster to run them locally (via `./swanky lint`), rather than waiting for CI to tell you that there was a failure.

#### Git Branching Style

We follow the [Github Flow](https://docs.github.com/en/get-started/quickstart/github-flow) git branching workflow. `dev` is the main branch of the Swanky repo. In this workflow, you:

1. Branch off the target branch (typically `dev`)
2. Commit and push your changes to the branch
3. Open a [Merge Request](#merge-requests) from your branch to the target branch.
4. Have a [Code Review](#code-review)
5. Merge the branch in, and then delete the feature branch.

If a project demands it, you can merge into a project-specific branch, before merging the project-specific branch into `dev`, but it's preferable to just work off of `dev`.

#### Branch Naming

We generate a lot of branches! In order to keep them tidy, it can be helpful to name branches like:

* **Feature Branches:** `feature/<name>`
* **Refactor Branches:** `refactor/<name>`
* **Experimental Branches:** `experimental/<name>`
* **Bugfix Branches:** `bugfix/<name>`

### `CODEOWNERS`

Each component[^what-is-a-component] of Swanky is owned by a team of at least _two_ people. This information is recorded in our [`CODEOWNERS`](https://docs.gitlab.com/ee/user/project/codeowners/) file.

[^what-is-a-component]: A component of Swanky ought to be one crate. However, there are some crates, like ocelot, which contain many different protocols and components. Until they get broken up into several different crates, different modules in ocelot might have distinct code owners.

The code owners are responsible for shepherding the components that they own, including:

* **Reviewing code which modifies their components.** Gitlab will automatically ask code owners to review any merge request which modifies code that they own.
* **Managing the health of the component.** This includes triaging issues which may impact the component.
* **Fielding questions about the component.** The code owners should be the resident experts on the components they own.
* **Documenting their component.** Someone should be able to read documentation to get fully up-to-speed on a component, without _needing_ to speak to one of its code owners. (We want code owners to be able to field questions because it's faster than _requiring_ everyone who has a question about a component to put in the leg work to learn about it.)

  We want to ensure that there's enough written down so that we can get new code owners up-to-speed, even if existing code owners are unavailable.

These responsibilities may consume hours. For example, if project A funds a 1,000 line code change to library B, project A could fund a code owner of library B for the 1-2 hours it would take to review the change.

### Code Review

The number one rule of code review is: "be kind!" Someone spent time writing the contribution that you are looking at. Code review provides a wonderful teaching/learning opportunity for everyone involved—treat it that way!

One goal of code review is to try to help avoid mistakes in code, or point out ways that it could be better. Beyond that, after a successful code review, reviewers should walk away with a deep understanding of the code that they just read. If none of the reviewers feel like they have a deep understanding of the code, it suggests that _something_ should be revisited: is the code confusing? Is it not the specialty of the reviewers?

After a successful code review, once the "Merge it In!" button has been pressed, the responsibility of the code should lie with the whole team. If the code has a bug in it, that's not the responsibility of the person who typed it; it's the responsibility of the whole team. On a healthy team, individuals aren't responsible for success or failure. The team should succeed or fail as a group, and code review is an important practice to make that a reality.

#### Tips for Code Review

If you ask a reviewer to review too much code it can be overwhelming. Instead, break the code into many smaller pieces, that can be reviewed separately.

Ask questions of the code author in comments! If you have a question about the code, it can help indicate that code should be restructured or differently documented. At worst, it'll help your understanding!

### AI Tools

AI tools CAN be used in contributions to Swanky AS LONG AS they follow the below requirements:

* For any new functionality, any public APIs and integration tests MUST be human
  authored, and done BEFORE using any AI tools.
* All API documentation MUST be human authored.
* All commits MUST be human authored (messages and choice of contents).
* The use of AI generated code in any commit MUST be disclosed in the commit
  message.
* We _strongly_ RECOMMEND the use of test-driven development as part of using AI.
* THE HUMAN AUTHOR IS RESPONSIBLE FOR ALL CODE IN A COMMIT. In addition, the
  human author is responsible for following commit best practices, such as
  having each commit only relate to a single change, commits being sufficiently
  small in scope, etc.
