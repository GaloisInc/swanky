use std::{fs::File, path::PathBuf};

use clap::{Parser, Subcommand};
use eyre::Context;
use mac_n_cheese_event_log::{EventLogEntry, EventLogReader, EventLogSchema};
use mac_n_cheese_ir::compilation_format::{GraphDegreeCount, Manifest, TaskKind, Type};
use std::fmt::Write as _;
use std::io::{BufWriter, Write};

/// Inspect full fat mac n'cheese circuits.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a graphviz representation of the IR
    Dot {
        circuit: PathBuf,
        /// Where should the output be written? Defaults to using <CIRCUIT>.dot
        #[clap(short, long)]
        output: Option<PathBuf>,
    },
    ReadEventLog {
        src: PathBuf,
    },
}

fn generate_graphviz(circuit: File, mut out: File) -> eyre::Result<()> {
    let circuit = Manifest::read(circuit).context("Reading circuit manifest")?;
    let manifest_hash = circuit.hash();
    let manifest = circuit.manifest();
    writeln!(out, "digraph X {{")?;
    writeln!(out, "node [shape=Mrecord];")?;
    writeln!(out, "fontname=\"Source Code Pro,Menlo,monospace\";")?;
    writeln!(out, "labelloc=\"t\";")?;
    let prototypes = manifest.prototypes();
    let mut in_degree = vec![0_u64; manifest.tasks().len()];
    let mut out_degree = vec![0_u64; manifest.tasks().len()];
    for (task_id, task) in manifest.tasks().iter().enumerate() {
        let mut label = format!(
            "{:?} P{} #{}",
            prototypes.get(task.prototype_id() as usize).kind()?,
            task.inferred_priority(),
            task_id
        );
        if let Some(name) = task.name() {
            write!(label, " {name}").unwrap();
        }
        if let Some(proto_name) = prototypes.get(task.prototype_id() as usize).name() {
            write!(label, " proto={proto_name}").unwrap();
        }
        writeln!(out, "subgraph cluster_{} {{", task_id)?;
        writeln!(out, "label = {:?};", label)?;
        let mut body_label = String::new();
        let mut first = true;
        let in_degree = &mut in_degree[task_id];
        let mut on_input = |src| {
            *in_degree += 1;
            *out_degree
                .get_mut(src)
                .ok_or_else(|| eyre::eyre!("Invalid task id"))? += 1;
            eyre::ensure!(src < task_id, "forwards task reference");
            Ok(())
        };

        for (input_idx, input) in task.single_array_inputs().iter().enumerate() {
            on_input(input.source().id() as usize)?;
            if first {
                first = false;
            } else {
                write!(body_label, "|").unwrap();
            }
            let ty = Type::try_from(*input.ty())?;
            write!(body_label, "<input{}> {:?} S#{}", input_idx, ty, input_idx).unwrap();
            writeln!(
                out,
                "T{} -> \"T{}\":input{} [label=\"{}..{} {:?}\"]",
                input.source().id(),
                task_id,
                input_idx,
                input.start(),
                input.end(),
                ty,
            )?;
        }
        for (input_idx, inputs) in task.multi_array_inputs().iter().enumerate() {
            if first {
                first = false;
            } else {
                write!(body_label, "|").unwrap();
            }
            let ty = Type::try_from(*inputs.ty())?;
            write!(body_label, "<input{}> {:?} S#{}", input_idx, ty, input_idx).unwrap();
            for tributary in inputs.inputs() {
                on_input(tributary.source().id() as usize)?;
                writeln!(
                    out,
                    "T{} -> \"T{}\":input{} [label=\"{}..{} {:?}\"]",
                    tributary.source().id(),
                    task_id,
                    input_idx,
                    tributary.start(),
                    tributary.end(),
                    ty,
                )?;
            }
        }
        writeln!(out, "T{} [label={:?}];", task_id, body_label)?;
        writeln!(out, "}}")?;
    }
    // Check that the degrees match what's on disk.
    let mut buf = Vec::new();
    buf.resize(manifest.dependent_counts().length() as usize, 0);
    circuit.read_data_chunk(manifest.dependent_counts(), &mut buf)?;
    let counts: &[GraphDegreeCount] = bytemuck::cast_slice(&buf);
    eyre::ensure!(
        counts.len() == out_degree.len(),
        "counts have the wrong length"
    );
    for (a, b) in counts.iter().zip(out_degree.iter()) {
        eyre::ensure!(u64::from(*a) == *b, "count mismatch");
    }
    buf.resize(manifest.dependency_counts().length() as usize, 0);
    circuit.read_data_chunk(manifest.dependency_counts(), &mut buf)?;
    let counts: &[GraphDegreeCount] = bytemuck::cast_slice(&buf);
    eyre::ensure!(
        counts.len() == in_degree.len(),
        "counts have the wrong length"
    );
    for (a, b) in counts.iter().zip(in_degree.iter()) {
        eyre::ensure!(u64::from(*a) == *b, "count mismatch");
    }
    writeln!(out, "subgraph  cluster_allocations{{")?;
    writeln!(out, "label={:?};", "Allocation Sizes")?;
    let mut label = String::new();
    label.push('{');
    for (i, asz) in manifest.allocation_sizes().iter().enumerate() {
        if i > 0 {
            label.push_str("| ");
        }
        write!(
            label,
            "<f{i}> {}",
            match asz.type_() {
                Some(ty_encoded) => format!("{} {:?}", asz.count(), Type::try_from(*ty_encoded)?),
                None => format!("{} bytes", asz.count()),
            }
        )
        .unwrap();
    }
    label.push('}');
    writeln!(out, "asz_contents [shape={:?}, label={label:?}]", "record")?;
    writeln!(out, "}}")?;
    writeln!(out, "subgraph cluster_task_kinds_used {{")?;
    writeln!(out, "label={:?};", "Task Kinds Used")?;
    let mut label = String::new();
    label.push('{');
    for (i, tsk) in manifest.task_kinds_used().iter().enumerate() {
        if i > 0 {
            label.push_str("| ");
        }
        write!(label, "<f{i}> {:?}", TaskKind::try_from(tsk)?).unwrap();
    }
    label.push('}');
    writeln!(out, "tku_contents [shape={:?}, label={label:?}]", "record")?;
    writeln!(out, "}}")?;
    writeln!(
        out,
        "label={:?}",
        format!("Mac n'Cheese Circuit Manifest {manifest_hash:X}")
    )?;
    writeln!(out, "}}")?;
    Ok(())
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    match args.cmd {
        Command::Dot { circuit, output } => {
            let circuit_file =
                File::open(&circuit).with_context(|| format!("Unable to open {circuit:?}"))?;
            let output = output.unwrap_or_else(|| circuit.with_extension("dot"));
            let output_file =
                File::create(&output).with_context(|| format!("Unable to create {output:?}"))?;
            generate_graphviz(circuit_file, output_file).with_context(|| {
                format!("Generating graphviz for {circuit:?} and writing it to {output:?}")
            })?;
        }
        Command::ReadEventLog { src } => {
            #[derive(serde::Serialize)]
            struct EventLog {
                schema: EventLogSchema,
                events: Vec<EventLogEntry>,
            }
            let mut r = EventLogReader::open(src)?;
            let mut evts = Vec::new();
            while let Some(evt) = r.next_event()? {
                evts.push(evt.clone());
            }
            let stdout_holder = std::io::stdout();
            ciborium::ser::into_writer(
                &EventLog {
                    schema: r.schema().clone(),
                    events: evts,
                },
                BufWriter::new(stdout_holder.lock()),
            )?;
        }
    }
    Ok(())
}
