name := "encrypted"

version := "0.1.1"

scalaVersion := "2.11.12"

homepage := Some(url("https://github.com/greywombat/encrypted"))

scmInfo := Some(ScmInfo(url("https://github.com/greywombat/encrypted"), "git@github.com:greywombat/encrypted.git"))

developers := List(Developer("greywombat", "Florian Kreitmair", "florian.kreitmair@tum.de", url("https://github.com/greywombat")))

licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0"))

publishMavenStyle := true

scalacOptions in(Compile, doc) ++= Seq("-groups", "-implicits")

libraryDependencies ++= Seq(
  "org.abstractj.kalium" % "kalium" % "0.7.0",
  "org.scalatest" %% "scalatest" % "3.0.4" % "test"
)
