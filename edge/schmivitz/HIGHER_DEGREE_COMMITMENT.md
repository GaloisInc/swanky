# Higher-Degree VOLE Commitments

Below is a description of the VOLE commitments and batched constraint check used for higher-degree gates in Schmivitz, following [2026-Agarwal-Baum-Braun-Scholl].

## Protocol setting

Let $`\mathbb{F}_p`$ be a finite base field, and let $`\mathbb{F}_{p^r}`$ be an extension field.
The protocol has two parties: a prover $`\mathcal{P}`$ and a verifier $`\mathcal{V}`$.
They agree on a computation, while $`\mathcal{P}`$ holds secret inputs and proves that evaluating the computation on those inputs gives the claimed result.

The construction has two main components:

1. commitment polynomials that support the circuit's gate operations; and
2. a batch protocol that checks many commitment polynomials of different degrees at once.

## Base VOLE

A call to $`\operatorname{VOLE}(n)`$ produces $n$ correlated triples.
For each $`i \in \{1,\ldots,n\}`$, the prover receives a random value $`u_i \in \mathbb{F}_p`$ and a mask $`w_i \in \mathbb{F}_{p^r}`$, and the verifier receives a global key $`\Delta \in \mathbb{F}_{p^r}`$ and a tag $`v_i \in \mathbb{F}_{p^r}`$, such that

```math
v_i = u_i\Delta + w_i.
```

Here $`u_i`$ is embedded naturally from $`\mathbb{F}_p`$ into $`\mathbb{F}_{p^r}`$ in the product $`u_i\Delta`$.

## Commitment polynomials

Definition 2 ("VOLE Commitment") of [2026-Agarwal-Baum-Braun-Scholl] defines the commitment polynomial used here. To commit to a value $`x \in \mathbb{F}_p`$, the prover holds a degree-$`d`$ polynomial

```math
\rho_x(t)
  = \rho_0 + \rho_1t + \cdots + \rho_{d-1}t^{d-1} + x t^d,
\qquad
\rho_0,\ldots,\rho_{d-1} \in \mathbb{F}_{p^r}.
```

Thus, the committed value $`x`$ is the highest-degree coefficient, while the lower coefficients mask it.
The verifier holds a global key $`\Delta \in \mathbb{F}_{p^r}`$ that is unknown to the prover, together with the evaluation

```math
\gamma_x = \rho_x(\Delta).
```

Degree one recovers the base VOLE relation: $`\rho_x(t)=w+xt`$ and $`\gamma_x=w+x\Delta`$.
Let $`\llbracket x \rrbracket_d`$ denote a degree-$`d`$ commitment represented by $`\rho_x`$ on the prover side and $`\gamma_x`$ on the verifier side.

## Gate-by-gate commitment propagation

The gate-by-gate evaluation below is the computation performed by `VOLE-ZK.Eval` in Figure 3 of [2026-Agarwal-Baum-Braun-Scholl],
using the homomorphic operations defined after Definition 2.
Commitment polynomials are constructed bottom-up through circuits containing addition,
addition by a constant, multiplication, and multiplication by a constant.
Every rule preserves two invariants: the output polynomial's leading coefficient is the output wire value, and the verifier's value is the output polynomial evaluated at $`\Delta`$.

- **Addition.**

  Given $`\llbracket x \rrbracket_{d_1}`$ and $`\llbracket y \rrbracket_{d_2}`$, let $`d=\max(d_1,d_2)`$.
  Align both leading coefficients at degree $`d`$ before adding:

  ```math
  \llbracket x+y \rrbracket_d:
  \qquad
  \rho_{x+y}(t)
    = t^{d-d_1}\rho_x(t)+t^{d-d_2}\rho_y(t),
  ```

  ```math
  \gamma_{x+y}
    = \Delta^{d-d_1}\gamma_x+\Delta^{d-d_2}\gamma_y.
  ```

  The powers of $t$ and $\Delta$ perform the same degree alignment on the prover and verifier sides.

- **Addition by a constant.**

  For $`\llbracket x \rrbracket_d`$ and $`c \in \mathbb{F}_p`$, define

  ```math
  \llbracket x+c \rrbracket_d:
  \qquad
  \rho_{x+c}(t)=\rho_x(t)+c\,t^d,
  \qquad
  \gamma_{x+c}=\gamma_x+c\,\Delta^d.
  ```

  Only the leading coefficient changes, so the commitment remains degree $`d`$.

- **Multiplication by a constant.**

  For $`\llbracket x \rrbracket_d`$ and $`c \in \mathbb{F}_p`$, define

  ```math
  \llbracket cx \rrbracket_d:
  \qquad
  \rho_{cx}(t)=c\,\rho_x(t),
  \qquad
  \gamma_{cx}=c\,\gamma_x.
  ```

  Scalar multiplication does not change the degree.

- **Multiplication.**

  Given $`\llbracket x \rrbracket_{d_1}`$ and $`\llbracket y \rrbracket_{d_2}`$, define

  ```math
  \llbracket xy \rrbracket_{d_1+d_2}:
  \qquad
  \rho_{xy}(t)=\rho_x(t)\rho_y(t),
  \qquad
  \gamma_{xy}=\gamma_x\gamma_y.
  ```

  Polynomial multiplication makes the output degree $`d_1+d_2`$, and evaluation at $`\Delta`$ remains multiplicative.

## Batched verification

This section follows `VOLE-ZK.BatchVer` in Figure 3 of [2026-Agarwal-Baum-Braun-Scholl], with the Schmivitz adaptations identified below.

0. **Fix the batch inputs.** The subprotocol is invoked as

   ```math
   \operatorname{VOLE-ZK.BatchVer}
     \bigl(\llbracket z_1\rrbracket_{d_1},\ldots,
           \llbracket z_m\rrbracket_{d_m}\bigr)
   ```

   on $`m`$ commitments. For each $`i\in\{1,\ldots,m\}`$, $`z_i\in\mathbb{F}_p`$ is the committed constraint value and $`d_i`$ is the degree of its commitment polynomial.

1. **Fix the batch degree.** For commitment degrees $`d_1,\ldots,d_m`$, let

   ```math
   d=\max\{d_1,\ldots,d_m\}.
   ```

   Thus, $`d`$ is the maximum degree among the $m$ input commitment polynomials. Step 6 aligns every input polynomial to degree $`d`$ before combining them into one polynomial.

2. **Generate masking commitments.** For every $`j\in\{1,\ldots,d-1\}`$, the paper invokes sVOLE to obtain degree-one commitments to base-field coordinates $`s_{j,0},\ldots,s_{j,r-1}\in\mathbb{F}_p`$.
   For each $`k\in\{0,\ldots,r-1\}`$, name the three correlated values as follows:

   ```math
   s_{j,k} \in \mathbb{F}_p,
   \qquad
   w_{j,k} \in \mathbb{F}_{p^r},
   \qquad
   v_{j,k} \in \mathbb{F}_{p^r}.
   ```

   The prover holds the value $`s_{j,k}`$ and mask $`w_{j,k}`$, while the verifier holds the tag $`v_{j,k}`$. They satisfy

   ```math
   v_{j,k} = w_{j,k} + s_{j,k}\Delta.
   ```

   Equivalently, $`\llbracket s_{j,k}\rrbracket_1`$ is represented by the degree-one polynomial

   ```math
   \sigma_{j,k}(t) = w_{j,k} + s_{j,k}t
   ```

   on the prover side and by $`v_{j,k}=\sigma_{j,k}(\Delta)`$ on the verifier side.
   Schmivitz obtains the equivalent masking material from its VOLE backend; the construction does not assume a fixed value of $r$.

3. **Compose the full-field masking commitments.** Let $`\alpha\in\mathbb{F}_{p^r}`$ be such that $`(1,\alpha,\ldots,\alpha^{r-1})`$ is an $`\mathbb{F}_p`$-basis of $`\mathbb{F}_{p^r}`$. For every $`j\in\{1,\ldots,d-1\}`$, apply the same linear combination to the value, mask, and tag:

   ```math
   s_j=\sum_{k=0}^{r-1}s_{j,k}\alpha^k,
   \qquad
   w_j=\sum_{k=0}^{r-1}w_{j,k}\alpha^k,
   \qquad
   \nu_j=\sum_{k=0}^{r-1}v_{j,k}\alpha^k.
   ```

   All three combined values belong to $`\mathbb{F}_{p^r}`$. On the prover side, this gives

   ```math
   \llbracket s_j\rrbracket_1
     =\sum_{k=0}^{r-1}\llbracket s_{j,k}\rrbracket_1\alpha^k,
   \qquad
   \sigma_{s_j}(t)
     =\sum_{k=0}^{r-1}\sigma_{j,k}(t)\alpha^k
     =s_jt+w_j.
   ```

   On the verifier side, the same combination preserves the VOLE equation:

   ```math
   \begin{aligned}
   \nu_j
     &=\sum_{k=0}^{r-1}v_{j,k}\alpha^k \\
     &=\sum_{k=0}^{r-1}
         \bigl(s_{j,k}\Delta+w_{j,k}\bigr)\alpha^k \\
     &=s_j\Delta+w_j \\
     &=\sigma_{s_j}(\Delta).
   \end{aligned}
   ```

   Thus, the prover holds the linear and constant coefficients $`(s_j,w_j)`$ of $`\sigma_{s_j}(t)`$, while the verifier holds the corresponding evaluation $`\nu_j`$. For $`d\le 1`$, there are no masking commitments and the corresponding sums below are empty.

4. **Identify the constraint polynomials.** Let $`\rho_i(t)=\rho_{z_i}(t)`$ be the degree-at-most-$`d_i`$ polynomial for constraint value $`z_i`$, and let $`\gamma_i=\rho_i(\Delta)`$.
   The constraint $`z_i=0`$ holds exactly when $`\rho_i`$ has degree at most $`d_i-1`$.

5. **Choose challenge weights.** The verifier sends a challenge
   $`(\chi_1,\ldots,\chi_m)\leftarrow\mathbb{F}_{p^r}^m`$.

6. **Compute and send the prover polynomial.** First align each of the $`m`$ constraint polynomials to the maximum degree $`d`$ and combine them into one challenge-weighted polynomial:

   ```math
   A(t)=\sum_{i=1}^{m}\chi_i\,t^{d-d_i}\rho_i(t),
   ```

   For each $`i`$, multiplication by $`t^{d-d_i}`$ moves the coefficient $`z_i`$ to degree $`d`$. Thus, the degree-$`d`$ coefficient of the single aggregate $`A(t)`$ is $`\sum_i\chi_i z_i`$ and vanishes when all constraints hold. The prover then forms

   ```math
   \pi(t)=A(t)+\sum_{j=1}^{d-1}t^{j-1}\sigma_{s_j}(t).
   ```

   The masking terms have degree at most $`d-1`$, so the degree-$`d`$ coefficient of $`\pi(t)`$ must also vanish. The paper has the prover send $`\pi(t)`$ as a degree-at-most-$`(d-1)`$ polynomial. Write

   ```math
   \pi(t)=\sum_{k=0}^{d-1}\pi_k t^k,
   ```

   where $`\pi_k\in\mathbb{F}_{p^r}`$ is the coefficient of $`t^k`$. Schmivitz sends the coefficient list $`\pi_0,\ldots,\pi_{d-1}`$ and omits the required zero coefficient at degree $`d`$.

7. **Compute and verify the verifier value.** Using the $`d-1`$ mask tags defined above, compute

   ```math
   q
     =\sum_{i=1}^{m}\chi_i\Delta^{d-d_i}\gamma_i
      +\sum_{j=1}^{d-1}\Delta^{j-1}\nu_j.
   ```
   Figure 3 prints $`d`$ as the upper limit of the second sum, but its preceding steps define and use only $`d-1`$ masks; Schmivitz uses the consistent upper limit $`d-1`$ shown here.
   Accept exactly when

   ```math
   \pi(\Delta)=\sum_{k=0}^{d-1}\pi_k\Delta^k=q
   ```

   and the transmitted polynomial has degree at most $`d-1`$.
   The equality checks the prover's aligned and masked polynomial at the verifier's secret point; Schmivitz enforces the degree bound through the transmitted coefficient count.

## Schmivitz integration

The polynomial-gate API belongs in `edge/sieve-ir-api`, and the protocol implementation belongs in `edge/schmivitz`.
Schmivitz instantiates the construction with `F2` as the base field and `F128b` as the extension field.

`edge/sieve-ir-api` defines the cross-crate circuit interface: `HigherDegreeBackend` adds the four polynomial gate operations and higher-degree zero assertion, while `HigherDegreeCircuitExecuter` lets a circuit execute against any such backend.

Unlike step 5, Schmivitz uses successive powers of one Fiat–Shamir challenge, shared across ordinary and higher-degree checks.
The paper's independent-weight batching bound therefore needs a separate justification for this adaptation.

`src/higher_degree_commitment` contains the protocol primitives: `CommitmentPolynomialProver` stores the
prover's coefficients, while `CommitmentPolynomialVerifier` stores the verifier's evaluation and
commitment degree. Both types implement the gate algebra.
`batch_verification` implements generic streamed prover and verifier accumulators for mixed-degree
alignment, masking, and the final batch check; each accumulator accepts its corresponding commitment type.
The accumulators are parameterized by the base field, extension field, and an `ExtensionFieldLifter`.
The batch protocol uses the operations provided by the `ExtensionFieldLifter` trait to compose values,
masks, and tags.

`ProverPreparer` performs the initial cleartext traversal with polynomial degrees as its higher-degree wire representation, determining the circuit's maximum constraint degree and therefore the amount of masking VOLE material to reserve.

`ProverTraverser` builds and batches `CommitmentPolynomialProver` values, while `VerifierTraverser` mirrors
the same gates using `CommitmentPolynomialVerifier` values and batches the resulting constraint evaluations.

`src/proof.rs` orchestrates these stages: `HigherDegreeCircuitAdapter` connects the higher-degree circuit API to the existing `FancyCircuit` pipeline, the higher-degree proof entry points reserve the extra VOLEs, and proof generation and verification finalize the accumulators and bind the masked polynomial coefficients into the transcript and proof.

## Reference

- [2026-Agarwal-Baum-Braun-Scholl]. Amit Agarwal, Carsten Baum, Lennart Braun, and Peter Scholl. *Low-Bandwidth Mixed Arithmetic in VOLE-Based ZK from Low-Degree PRGs*. EUROCRYPT 2025.

[2026-Agarwal-Baum-Braun-Scholl]: https://artifacts.iacr.org/eurocrypt/2025/a8/
