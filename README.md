# Yesterday Once More

Recreating historical internet attacks and incidents to understand how they
happened, how they worked, and what we can learn from them.

Yesterday Once More brings together documented recreations of past incidents
and the software needed to reproduce them. The goal is to turn historical
events into repeatable experiments that can be studied and explored.

## What belongs here

- **Case recreations:** Historical context, technical explanations, experiment
  environments, and step-by-step instructions for reproducing past internet
  attacks and incidents in controlled lab environments.
- **Supporting software:** Tools and components developed to make those
  recreations possible, including software that can be reused across cases.
- **Documentation:** Setup guides, design notes, references, and explanations
  of the observations and lessons from each recreation.

## Project status

The project is at its initial scaffolding stage. No source code, case studies,
documentation, or runnable examples have been added yet. Build, installation,
and usage instructions will be documented as the project develops.

## Directory layout

The working directory is organized into the following folders, which are
currently empty:

| Directory | Intended contents |
| --- | --- |
| `cases/` | Recreations of historical attacks and incidents, with case-specific instructions and materials |
| `docs/` | Shared setup guides, technical explanations, and project documentation |
| `images/` | Docker images and build materials used to recreate attacks and incidents |
| `software/` | Software and reusable tools developed to support the recreations |

Git does not track empty directories, so these folders may not appear in a
fresh clone until files are added to them.

## Getting started

Clone the repository:

```sh
git clone https://github.com/seed-labs/yesterday-once-more.git
cd yesterday-once-more
```

There are currently no dependencies to install or build commands to run.

## Contributing

Contributions can include new case recreations, improvements to existing cases,
supporting software, or documentation. Open an issue to discuss a proposed case
or tool, or submit a pull request.

For a case recreation, include the historical background and sources, the
required environment, reproduction steps, and expected observations. Explain
any simplifications or differences from the original incident. For supporting
software, document its purpose, setup, usage, and the cases it supports.

## License

See [LICENSE](LICENSE) for the GNU General Public License, version 3.
