import java.security.SecureRandom
import java.security.MessageDigest

object Main {

  def main(args: Array[String]): Unit = {
    val (sec1, sec2, pub) = Lamport.generateKey()
    val sig               = Lamport.sign("sample message of lamport signature", sec1, sec2)
    val result            = Lamport.verify("sample message of lamport signature", pub, sig)
    println(if (result) "Valid" else "Invalid")
  }
}

object Lamport {
  val secureRandom = new SecureRandom
  val digest       = MessageDigest.getInstance("SHA-256")
  val CHUNK_SIZE   = 8
  val BLOCK_SIZE   = 256

  implicit class ArrayByte(one: Array[Byte]) {

    def toChunk: Seq[Array[Byte]] = {
      def inner(ret: Seq[Array[Byte]], rest: Array[Byte]): Seq[Array[Byte]] = rest match {
        case _ if rest.length == 0 => ret
        case _ => {
          inner(ret.appended(rest.take(CHUNK_SIZE)), rest.drop(CHUNK_SIZE))
        }
      }
      inner(Seq(), one)
    }

    def equ(that: Array[Byte]): Boolean = {
      one.length == that.length match {
        case false => false
        case true =>
          !(
            one
              .zip(that)
              .map(tup => {
                tup._1 == tup._2
              })
              .exists(bool => !bool)
          )
      }
    }
  }

  implicit class ArrayInt(one: Array[Int]) {

    def toBitRepresentaion: Array[String] = one.map(eightBit =>
      String.format("%8s", Integer.toBinaryString(eightBit & 0xff)).replace(' ', '0')
    )
  }

  def generateKey() = {
    val sec1                  = secureRandom.generateSeed(CHUNK_SIZE * BLOCK_SIZE).toChunk
    val sec2                  = secureRandom.generateSeed(CHUNK_SIZE * BLOCK_SIZE).toChunk
    val pub: Seq[Array[Byte]] = (sec1 ++ sec2).map(digest.digest)

    (sec1, sec2, pub)
  }

  def sign(message: String, sec1: Seq[Array[Byte]], sec2: Seq[Array[Byte]]): Seq[Array[Byte]] = {
    val chooseSecret: ((Char, Int)) => Array[Byte] = (tup) => {
      tup._1 match {
        case '0' => sec1(tup._2)
        case '1' => sec2(tup._2)
      }
    }
    digest
      .digest(message.getBytes())
      .map(_.toInt)
      .toBitRepresentaion
      .mkString("")
      .zipWithIndex
      .map[Array[Byte]] { chooseSecret }
      .toSeq
  }

  def verify(message: String, pubKey: Seq[Array[Byte]], sig: Seq[Array[Byte]]): Boolean = {
    val verifier: ((Char, Int)) => Boolean = (tup) => {
      tup._1 match {
        case '0' => digest.digest(sig(tup._2)) equ pubKey(tup._2)
        case '1' => digest.digest(sig(tup._2)) equ pubKey(tup._2 + BLOCK_SIZE)
      }
    }
    digest
      .digest(message.getBytes())
      .map(_.toInt)
      .toBitRepresentaion
      .mkString("")
      .zipWithIndex
      .map[Boolean] { verifier }
      .forall(b => b)
  }
}
