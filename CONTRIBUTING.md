# Contributing to Swanky

This document is still a work in progress. More information will be added later.

:wave: Hello newcomer to Swanky! This document contains a lot of _stuff_ about our development process. Here are the most important sections for introducing you to Swanky:

1. [Code of Conduct](CODE_OF_CONDUCT.md)
2. [Goals of Swanky](#goals-of-swanky)
3. [Swanky Development Process](CONTRIBUTING/swanky-development-process.md)
4. [Swanky Implementation Information](CONTRIBUTING/swanky-implementation-info.md)
5. [Swanky and AI Tools](#swanky-and-ai-tools)
6. [Swanky API Guidelines](#swanky-api-guidelines)

The first two sections of this document describes the _process_ of developing Swanky (e.g. how to go about adding a new feature, how to structure code review, etc.). The remainder of this document is about technical considerations when developing for Swanky.

In this document, we aim to emphasize _why_ we recommend the practices outlined in this document. If there's some development practice that doesn't have a good reason behind it, then we shouldn't be doing it!

Parts of Swanky currently diverge from these standards. We are working to help align all of Swanky with these standards.

[[_TOC_]]

## Goals of Swanky

Swanky is a development platform for cryptographic research, intended for prototyping cryptographic protocols and implementation techniques. For Swanky to accelerate research and prototyping, it must provide a stable foundation that we can build on: it must be understandable, well-written, and well-designed. We'd rather our users be making progress instead of figuring out why some five-year-old library panics exclusively during the waxing gibbous moon. While there is some cost to developing Swanky-destined cryptography in such a manner, we believe that using software engineering practices to develop a new Swanky component will not only help streamline the development of this new component, but will also make it easier to re-use the component in the future. As they say, "one milligram of prevention is worth a centigram of cure."

Because Swanky is a research and prototyping platform, we prioritize work which is necessary to support those objectives over work to productionize the system. For example, Swanky does not currently implement protections against denial of service attacks. While these protections would be important in a production system, they aren't necessary to prove out ideas for our cryptographic research platform. Please reach out to us at <swanky@galois.com> if you're interested in using Swanky in a production setting.

## Swanky Development Process

See the [Swanky Development Process](CONTRIBUTING/swanky-development-process.md) document for details.

## Swanky Implementation Information

See the [Swanky Implementation Information](CONTRIBUTING/swanky-implementation-info.md) document for details.

## Swanky and AI Tools

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

## Swanky API Guidelines

We aim for Swanky to follow the
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
Currently the codebase does not consistently follow these guidelines.
All new code _must_ follow these guidelines, and we aim to refactor
existing code to follow these guidelines as well.
