initSidebarItems({"enum":[["Message","The outputs that can be emitted by a Garbler and consumed by an Evaluator."],["Wire","The essential wirelabel type used by garbled circuits."]],"fn":[["bench_garbling","Run benchmark garbling and streaming on the function. Garbling function is evaluated on another thread."],["garble","Garble a circuit without streaming."],["garble_iter","Create an iterator over the messages produced by fancy garbling."],["wires_from_bytes","Convert a slice of bytes back to wires."],["wires_to_bytes","Convert a slice of wires to bytes."]],"mod":[["circuit","DSL for creating circuits compatible with fancy-garbling in the old-fashioned way, where you create a circuit for a computation then garble it."],["dummy","Dummy implementation of Fancy."],["informer","Informer runs a fancy computation and learns information from it, like how many of what kind of inputs there are."],["util","Tools useful for interacting with `fancy-garbling`."]],"struct":[["Bundle","A collection of wires, useful for the garbled gadgets defined by `BundleGadgets`."],["Decoder","Decode outputs."],["Encoder","Encode inputs statically."],["Evaluator","Streaming evaluator using a callback to receive ciphertexts as needed."],["GarbledCircuit","Static evaluator for a circuit, created by the `garble` function."],["Garbler","Streams garbled circuit ciphertexts through a callback. Parallelizable."]],"trait":[["BundleGadgets","Extension trait for `Fancy` providing advanced gadgets based on bundles of wires."],["Fancy","DSL for the basic computations supported by fancy-garbling."],["HasModulus","An object that has some modulus. Basic object of Fancy compuations."]],"type":[["GarbledGate","The ciphertext created by a garbled gate."],["OutputCiphertext","Ciphertext created by the garbler for output gates."],["SyncIndex","The index of a thread for synchronization."]]});