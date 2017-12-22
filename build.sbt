name := "encrypted"

version := "0.1"

scalaVersion := "2.11.12"

scalacOptions in (Compile,doc) ++= Seq("-groups", "-implicits")

libraryDependencies ++= Seq(
  "org.abstractj.kalium" % "kalium" % "0.7.0",
  "org.scalatest" %% "scalatest" % "3.0.4" % "test"
)
