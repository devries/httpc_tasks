import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/io
import gleam/json
import gleam/list
import gleam/option
import gleam/otp/task
import gleam/pair
import gleam/result
import gleam/string
import simplifile

const cpe = "cpe:/o:redhat:enterprise_linux:8"

pub fn main() {
  use content <- result.map(
    simplifile.read("cvelist.txt")
    |> result.map_error(fn(e) {
      io.println("error reading file: " <> simplifile.describe_error(e))
    }),
  )

  content
  |> string.split("\n")
  |> list.map(string.trim)
  |> list.filter(fn(line) { line != "" })
  |> list.map(fn(s) { fn() { get_detail(s) } })
  |> batch_run(10, 200)
  |> list.each(fn(r) {
    let response =
      r
      |> result.replace_error("await error")
      |> result.flatten

    case response {
      Ok(detail) -> {
        let score_suffix = case detail.cvss {
          option.None -> ""
          option.Some(cvss) -> " --- Score: " <> cvss.score
        }

        io.println(detail.name <> ": " <> detail.severity <> score_suffix)

        detail.package_state
        |> list.each(fn(ps) {
          case ps.cpe == cpe {
            True -> io.println("\t" <> ps.package <> ": " <> ps.fix_state)
            False -> Nil
          }
        })
      }
      Error(e) -> io.println("Error: " <> e)
    }
  })
}

pub type CVSS {
  CVSS(score: String, vector: String, status: String)
}

pub type PackageState {
  PackageState(product: String, fix_state: String, package: String, cpe: String)
}

pub type CVE {
  CVE(
    name: String,
    severity: String,
    public_date: String,
    cvss: option.Option(CVSS),
    details: List(String),
    package_state: List(PackageState),
  )
}

pub fn parse_response(from body: String) -> Result(CVE, String) {
  let decoder = {
    use name <- decode.field("name", decode.string)
    use severity <- decode.field("threat_severity", decode.string)
    use public_date <- decode.field("public_date", decode.string)
    use cvss <- decode.optional_field("cvss3", option.None, {
      use score <- decode.field("cvss3_base_score", decode.string)
      use vector <- decode.field("cvss3_scoring_vector", decode.string)
      use status <- decode.field("status", decode.string)
      decode.success(option.Some(CVSS(score:, vector:, status:)))
    })
    use details <- decode.field("details", decode.list(decode.string))
    use package_state <- decode.field(
      "package_state",
      decode.list({
        use product <- decode.field("product_name", decode.string)
        use fix_state <- decode.field("fix_state", decode.string)
        use package <- decode.field("package_name", decode.string)
        use cpe <- decode.field("cpe", decode.string)
        decode.success(PackageState(product:, fix_state:, package:, cpe:))
      }),
    )
    decode.success(CVE(
      name:,
      severity:,
      public_date:,
      cvss:,
      details:,
      package_state:,
    ))
  }

  json.parse(from: body, using: decoder)
  |> result.map_error(fn(e) { "unable to parse json: " <> string.inspect(e) })
}

pub fn get_detail(cve: String) -> Result(CVE, String) {
  let url =
    "https://access.redhat.com/hydra/rest/securitydata/cve/" <> cve <> ".json"

  use req <- result.try({
    request.to(url)
    |> result.replace_error("Unable to build request for url " <> url)
  })

  use resp <- result.try(
    httpc.send(req)
    |> result.map_error(fn(e) {
      case e {
        httpc.InvalidUtf8Response -> "invalid response"
        httpc.FailedToConnect(_, _) -> "connection failure"
      }
    }),
  )

  parse_response(resp.body)
}

/// Run a set of functions asynchronously as OTP task in batches of the
/// given size (num). This function will wait forever, but checks for
/// completed jobs in intervals given by the timeout.
pub fn batch_run(
  work: List(fn() -> a),
  num: Int,
  timeout: Int,
) -> List(Result(a, task.AwaitError)) {
  let #(run_group, wait_group) = list.split(work, num)

  let running = run_group |> list.map(task.async)
  batch_run_group(running, wait_group, [], timeout)
}

fn batch_run_group(
  running: List(task.Task(a)),
  waiting: List(fn() -> a),
  done: List(Result(a, task.AwaitError)),
  timeout: Int,
) -> List(Result(a, task.AwaitError)) {
  case running {
    [] -> done
    _ -> {
      let results = task.try_await_all(running, timeout) |> list.zip(running)

      let #(finished, working) =
        results
        |> list.partition(fn(tup) {
          case tup {
            #(Error(task.Timeout), _) -> False
            _ -> True
          }
        })

      let finished_result =
        finished
        |> list.map(pair.first)

      let working_tasks =
        working
        |> list.map(pair.second)

      let n_to_add = list.length(finished)
      let #(to_add, new_waiting) = list.split(waiting, n_to_add)

      batch_run_group(
        list.append(to_add |> list.map(task.async), working_tasks),
        new_waiting,
        list.append(finished_result, done),
        timeout,
      )
    }
  }
}
