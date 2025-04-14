import gleam/dynamic/decode
import gleam/http/request
import gleam/httpc
import gleam/io
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import simplifile
import task_limiter

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
  |> task_limiter.async_await(10, 20)
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
